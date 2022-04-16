﻿/*
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

using Crypter.Common.Enums;
using Crypter.Contracts.Common;
using Crypter.Contracts.Features.Transfer.Upload;
using Crypter.Core.Interfaces;
using Crypter.CryptoLib.Services;
using Hangfire;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Crypter.API.Services
{
   public class UploadService
   {
      private readonly long AllocatedDiskSpace;
      private readonly long MaxUploadSize;

      private readonly IEmailService EmailService;
      private readonly IApiValidationService ApiValidationService;
      private readonly ISimpleEncryptionService SimpleEncryptionService;
      private readonly ISimpleHashService SimpleHashService;
      private readonly IUserService UserService;
      private readonly Func<byte[], byte[]> ItemDigestFunction;

      public UploadService(
         IConfiguration configuration,
         IEmailService emailService,
         IApiValidationService apiValidationService,
         ISimpleEncryptionService simpleEncryptionService,
         IUserService userService,
         ISimpleHashService simpleHashService
         )
      {
         AllocatedDiskSpace = long.Parse(configuration["EncryptedFileStore:AllocatedGB"]) * (long)Math.Pow(2, 30);
         MaxUploadSize = long.Parse(configuration["MaxUploadSizeMB"]) * (long)Math.Pow(2, 20);
         EmailService = emailService;
         ApiValidationService = apiValidationService;
         SimpleEncryptionService = simpleEncryptionService;
         UserService = userService;
         SimpleHashService = simpleHashService;
         ItemDigestFunction = SimpleHashService.DigestSha256;
      }

      private async Task<(bool Success, UploadTransferError ErrorCode, IBaseTransferItem? GenericTransferData, byte[]? ServerEncryptedCipherText)> ReceiveTransferAsync(IUploadTransferRequestBase request, Guid senderId, Guid recipientId, CancellationToken cancellationToken)
      {
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
      }

      public async Task<IActionResult> ReceiveMessageTransferAsync(UploadTransferRequest request, Guid senderId, string recipient, CancellationToken cancellationToken)
      {
         Guid recipientId = Guid.Empty;

         if (!string.IsNullOrEmpty(recipient))
         {
            var maybeUser = await UserService.ReadAsync(recipient, cancellationToken);
            if (maybeUser is null)
            {
               return new BadRequestObjectResult(new ErrorResponse(UploadTransferError.UserNotFound));
            }

            if (maybeUser is not null)
            {
               recipientId = maybeUser.Id;
            }
         }

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

      public async Task<IActionResult> ReceiveFileTransferAsync(UploadFileTransferRequest request, Guid senderId, string recipient, CancellationToken cancellationToken)
      {
         Guid recipientId = Guid.Empty;

         if (!string.IsNullOrEmpty(recipient))
         {
            var maybeUser = await UserService.ReadAsync(recipient, cancellationToken);

            if (maybeUser is null)
            {
               return new BadRequestObjectResult(new ErrorResponse(UploadTransferError.UserNotFound));
            }

            if (maybeUser is not null)
            {
               recipientId = maybeUser.Id;
            }
         }

         (var success, var errorCode, var genericTransferData, var ciphertextServerEncrypted) = await ReceiveTransferAsync(request, senderId, recipientId, cancellationToken);

         if (!success || genericTransferData is null)
         {
            return new BadRequestObjectResult(new ErrorResponse(errorCode));
         }

         var saveResult = await FileTransferItemStorageService.SaveAsync(genericTransferData.Id, ciphertextServerEncrypted, cancellationToken);
         if (!saveResult)
         {
            return new BadRequestObjectResult(new ErrorResponse(UploadTransferError.UnknownError));
         }

         var fileItem = new FileTransfer(
               genericTransferData.Id,
               senderId,
               recipientId,
               request.Filename,
               request.ContentType,
               genericTransferData.Size,
               genericTransferData.ClientIV,
               genericTransferData.Signature,
               genericTransferData.X25519PublicKey,
               genericTransferData.Ed25519PublicKey,
               genericTransferData.ServerIV,
               genericTransferData.ServerDigest,
               genericTransferData.Created,
               genericTransferData.Expiration);

         await FileTransferService.InsertAsync(fileItem, default);

         if (recipientId != Guid.Empty)
         {
            BackgroundJob.Enqueue(() => EmailService.HangfireSendTransferNotificationAsync(TransferItemType.File, fileItem.Id));
         }

         return new OkObjectResult(
             new UploadTransferResponse(genericTransferData.Id, genericTransferData.Expiration));
      }
   }
}
