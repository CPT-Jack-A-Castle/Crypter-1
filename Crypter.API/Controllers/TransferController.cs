/*
 * Copyright (C) 2022 Crypter File Transfer
 * 
 * This file is part of the Crypter file transfer project.
 * 
 * Crypter is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * The Crypter source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * You can be released from the requirements of the aforementioned license
 * by purchasing a commercial license. Buying such a license is mandatory
 * as soon as you develop commercial activities involving the Crypter source
 * code without disclosing the source code of your own applications.
 * 
 * Contact the current copyright holder to discuss commercial license options.
 */

using Crypter.API.Services;
using Crypter.Common.Monads;
using Crypter.Contracts.Common;
using Crypter.Contracts.Features.Transfer.DownloadCiphertext;
using Crypter.Contracts.Features.Transfer.DownloadPreview;
using Crypter.Contracts.Features.Transfer.DownloadSignature;
using Crypter.Contracts.Features.Transfer.Upload;
using Crypter.Core.Features.Transfer.Commands;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Crypter.API.Controllers
{
   [Route("api/transfer")]
   public class TransferController : ControllerBase
   {
      private readonly IMediator _mediator;
      private readonly ITokenService _tokenService;

      public TransferController(IMediator mediator, ITokenService tokenService)
      {
         _mediator = mediator;
         _tokenService = tokenService;
      }

      [HttpPost("message")]
      [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(UploadTransferResponse))]
      [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(ErrorResponse))]
      public async Task<IActionResult> UploadAnonymousMessageTransferAsync([FromBody] UploadMessageTransferRequest request, CancellationToken cancellationToken)
      {
         Maybe<Guid> senderId = _tokenService.TryParseUserId(User);

         var insertMessageCommand = new InsertAnonymousMessageTransferCommand(senderId, Maybe<Guid>.None, request.Subject);

         var insertMessageResult = await _mediator.Send(insertMessageCommand, cancellationToken);

         var serverHasSpaceRemaining = await ApiValidationService.IsEnoughSpaceForNewTransferAsync(AllocatedDiskSpace, MaxUploadSize, cancellationToken);
         if (!serverHasSpaceRemaining)
         {
            return (false, UploadTransferError.OutOfSpace, null, null);
         }

         byte[] hashedSymmetricEncryptionKey;
         try
         {
            hashedSymmetricEncryptionKey = Convert.FromBase64String(request.ServerEncryptionKeyBase64);
         }
         catch (Exception)
         {
            return (false, UploadTransferError.InvalidServerEncryptionKey, null, null);
         }

         byte[] originalCiphertextBytes;
         try
         {
            originalCiphertextBytes = Convert.FromBase64String(request.Ciphertext);
         }
         catch (Exception)
         {
            return (false, UploadTransferError.InvalidCipherText, null, null);
         }

         if (request.RequestedLifetimeHours > 24 || request.RequestedLifetimeHours < 1)
         {
            return (false, UploadTransferError.InvalidRequestedLifetimeHours, null, null);
         }

         // Digest the ciphertext BEFORE applying server-side encryption
         var serverDigest = ItemDigestFunction(originalCiphertextBytes);

         // Apply server-side encryption
         if (hashedSymmetricEncryptionKey.Length != 32)
         {
            return (false, UploadTransferError.InvalidServerEncryptionKey, null, null);
         }

         var (serverEncryptedCiphertext, serverIV) = SimpleEncryptionService.Encrypt(hashedSymmetricEncryptionKey, originalCiphertextBytes);

         Guid itemId = Guid.NewGuid();
         var created = DateTime.UtcNow;
         var expiration = created.AddHours(request.RequestedLifetimeHours);

         var returnItem = new BaseTransfer(itemId, senderId, recipientId, originalCiphertextBytes.Length, request.ClientEncryptionIVBase64, request.DigitalSignature, request.DiffieHellmanPublicKey, request.DigitalSignaturePublicKey, serverIV, serverDigest, created, expiration);
         return (true, UploadTransferError.UnknownError, returnItem, serverEncryptedCiphertext);

         (var success, var errorCode, var genericTransferData, var ciphertextServerEncrypted) = await ReceiveTransferAsync(request, senderId, recipientId, cancellationToken);

         if (!success || genericTransferData is null)
         {
            return new BadRequestObjectResult(new ErrorResponse(errorCode));
         }

         var saveResult = await MessageTransferItemStorageService.SaveAsync(genericTransferData.Id, ciphertextServerEncrypted, cancellationToken);
         if (!saveResult)
         {
            return new BadRequestObjectResult(new ErrorResponse(UploadTransferError.UnknownError));
         }

         var messageItem = new MessageTransfer(
               genericTransferData.Id,
               senderId,
               recipientId,
               request.Subject,
               genericTransferData.Size,
               genericTransferData.ClientIV,
               genericTransferData.Signature,
               genericTransferData.X25519PublicKey,
               genericTransferData.Ed25519PublicKey,
               genericTransferData.ServerIV,
               genericTransferData.ServerDigest,
               genericTransferData.Created,
               genericTransferData.Expiration);

         await MessageTransferService.InsertAsync(messageItem, default);

         if (recipientId != Guid.Empty)
         {
            BackgroundJob.Enqueue(() => EmailService.HangfireSendTransferNotificationAsync(TransferItemType.Message, messageItem.Id));
         }

         return new OkObjectResult(
             new UploadTransferResponse(genericTransferData.Id, genericTransferData.Expiration));
      }

      [HttpPost("message/{recipientUsername}")]
      [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(UploadTransferResponse))]
      [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(ErrorResponse))]
      public async Task<IActionResult> UploadUserMessageTransferAsync([FromBody] UploadMessageTransferRequest request, string recipientUsername, CancellationToken cancellationToken)
      {
         var senderId = _tokenService.TryParseUserId(User)
            .IfNone(Guid.Empty);
         return await _uploadService.ReceiveMessageTransferAsync(request, senderId, recipient, cancellationToken);
      }

      [HttpPost("file")]
      [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(UploadTransferResponse))]
      [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(ErrorResponse))]
      public async Task<IActionResult> FileTransferAsync([FromBody] UploadFileTransferRequest request, CancellationToken cancellationToken)
      {
         var senderId = _tokenService.TryParseUserId(User)
            .IfNone(Guid.Empty);
         return await _uploadService.ReceiveFileTransferAsync(request, senderId, string.Empty, cancellationToken);
      }

      [HttpPost("file/{recipientUsername}")]
      [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(UploadTransferResponse))]
      [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(ErrorResponse))]
      public async Task<IActionResult> UserFileTransferAsync([FromBody] UploadFileTransferRequest request, string recipientUsername, CancellationToken cancellationToken)
      {
         var senderId = _tokenService.TryParseUserId(User)
            .IfNone(Guid.Empty);
         return await _uploadService.ReceiveFileTransferAsync(request, senderId, recipient, cancellationToken);
      }

      [HttpPost("message/preview")]
      [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(DownloadTransferMessagePreviewResponse))]
      [ProducesResponseType(StatusCodes.Status404NotFound, Type = typeof(ErrorResponse))]
      public async Task<IActionResult> GetMessagePreviewAsync([FromBody] DownloadTransferPreviewRequest request, CancellationToken cancellationToken)
      {
         var requestorId = _tokenService.TryParseUserId(User)
            .IfNone(Guid.Empty);
         return await _downloadService.GetMessagePreviewAsync(request, requestorId, cancellationToken);
      }

      [HttpPost("file/preview")]
      [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(DownloadTransferMessagePreviewResponse))]
      [ProducesResponseType(StatusCodes.Status404NotFound, Type = typeof(ErrorResponse))]
      public async Task<IActionResult> GetFilePreviewAsync([FromBody] DownloadTransferPreviewRequest request, CancellationToken cancellationToken)
      {
         var requestorId = _tokenService.TryParseUserId(User)
            .IfNone(Guid.Empty);
         return await _downloadService.GetFilePreviewAsync(request, requestorId, cancellationToken);
      }

      [HttpPost("message/ciphertext")]
      [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(DownloadTransferCiphertextResponse))]
      [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(ErrorResponse))]
      [ProducesResponseType(StatusCodes.Status404NotFound, Type = typeof(ErrorResponse))]
      public async Task<IActionResult> GetMessageCiphertextAsync([FromBody] DownloadTransferCiphertextRequest request, CancellationToken cancellationToken)
      {
         var requestorId = _tokenService.TryParseUserId(User)
            .IfNone(Guid.Empty);
         return await _downloadService.GetMessageCiphertextAsync(request, requestorId, cancellationToken);
      }

      [HttpPost("file/ciphertext")]
      [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(DownloadTransferCiphertextResponse))]
      [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(ErrorResponse))]
      [ProducesResponseType(StatusCodes.Status404NotFound, Type = typeof(ErrorResponse))]
      public async Task<IActionResult> GetFileCiphertext([FromBody] DownloadTransferCiphertextRequest request, CancellationToken cancellationToken)
      {
         var requestorId = _tokenService.TryParseUserId(User)
            .IfNone(Guid.Empty);
         return await _downloadService.GetFileCiphertextAsync(request, requestorId, cancellationToken);
      }

      [HttpPost("message/signature")]
      [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(DownloadTransferSignatureResponse))]
      [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(ErrorResponse))]
      [ProducesResponseType(StatusCodes.Status404NotFound, Type = typeof(ErrorResponse))]
      public async Task<IActionResult> GetMessageSignatureAsync([FromBody] DownloadTransferSignatureRequest request, CancellationToken cancellationToken)
      {
         var requestorId = _tokenService.TryParseUserId(User)
            .IfNone(Guid.Empty);
         return await _downloadService.GetMessageSignatureAsync(request, requestorId, cancellationToken);
      }

      [HttpPost("file/signature")]
      [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(DownloadTransferSignatureResponse))]
      [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(ErrorResponse))]
      [ProducesResponseType(StatusCodes.Status404NotFound, Type = typeof(ErrorResponse))]
      public async Task<IActionResult> GetFileSignatureAsync([FromBody] DownloadTransferSignatureRequest request, CancellationToken cancellationToken)
      {
         var requestorId = _tokenService.TryParseUserId(User)
            .IfNone(Guid.Empty);
         return await _downloadService.GetFileSignatureAsync(request, requestorId, cancellationToken);
      }
   }
}