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

using Crypter.Common.Primitives;
using Crypter.Contracts.Features.Transfer.Upload;
using Crypter.CryptoLib;
using Crypter.CryptoLib.Crypto;
using Crypter.Web.Models;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crypter.Web.Shared.Transfer
{
   public partial class UploadFileTransferBase : UploadTransferBase
   {
      [Inject]
      public ClientAppSettings AppSettings { get; set; }

      protected const int MaxFileCount = 1;
      protected const int Base64SafeChunkSize = 60000;

      protected long MaxFileSizeBytes;
      protected bool ShowProgressBar = false;
      protected double ProgressPercent = 0.0;
      protected string DropClass = "";
      protected List<string> ErrorMessages = new();

      protected IBrowserFile SelectedFile;

      protected override void OnInitialized()
      {
         MaxFileSizeBytes = AppSettings.MaxUploadSizeMB * (long)Math.Pow(2, 20);
         base.OnInitialized();
      }

      protected void HandleDragEnter()
      {
         DropClass = "dropzone-drag";
      }

      protected void HandleDragLeave()
      {
         DropClass = "";
      }

      protected void HandleFileInputChange(InputFileChangeEventArgs e)
      {
         DropClass = "";
         ErrorMessages.Clear();

         var file = e.File;

         if (file == null)
         {
            ErrorMessages.Add("No file selected.");
            return;
         }

         if (file.Size > MaxFileSizeBytes)
         {
            ErrorMessages.Add($"The max file size is {AppSettings.MaxUploadSizeMB} MB.");
            return;
         }

         SelectedFile = file;
      }

      protected override async Task OnEncryptClicked()
      {
         if (SelectedFile is null)
         {
            ErrorMessages.Add("No file selected");
            return;
         }

         EncryptionInProgress = true;
         ErrorMessages.Clear();

         await SetNewEncryptionStatus("Generating keys");
         GenerateMissingAsymmetricKeys();

         PEMString senderX25519PrivateKey = PEMString.From(SenderX25519PrivateKey);
         PEMString senderEd25519PrivateKey = PEMString.From(SenderEd25519PrivateKey);
         PEMString recipientX25519PublicKey = PEMString.From(RecipientX25519PublicKey);

         (var sendKey, var serverKey) = DeriveSymmetricKeys(senderX25519PrivateKey, recipientX25519PublicKey);
         var iv = AES.GenerateIV();

         await SetNewEncryptionStatus("Encrypting your file");
         var partitionedCiphertext = await EncryptBytesAsync(SelectedFile, sendKey, iv);
         await HideEncryptionProgress();

         await SetNewEncryptionStatus("Signing your file");
         var signature = await SignBytesAsync(SelectedFile, senderEd25519PrivateKey);
         await HideEncryptionProgress();

         await SetNewEncryptionStatus("Uploading");
         var encodedCipherText = partitionedCiphertext
            .Select(x => Convert.ToBase64String(x))
            .ToList();

         var encodedECDHSenderKey = Convert.ToBase64String(
            Encoding.UTF8.GetBytes(KeyConversion.ConvertX25519PrivateKeyFromPEM(senderX25519PrivateKey).GeneratePublicKey().ConvertToPEM().Value));
         var encodedECDSASenderKey = Convert.ToBase64String(
            Encoding.UTF8.GetBytes(KeyConversion.ConvertEd25519PrivateKeyFromPEM(senderEd25519PrivateKey).GeneratePublicKey().ConvertToPEM().Value));
         var encodedServerEncryptionKey = Convert.ToBase64String(serverKey);
         var encodedSignature = Convert.ToBase64String(signature);
         var fileType = string.IsNullOrEmpty(SelectedFile.ContentType)
            ? "application/unknown"
            : SelectedFile.ContentType;
         var encodedClientIV = Convert.ToBase64String(iv);

         var request = new UploadFileTransferRequest(SelectedFile.Name, fileType, encodedCipherText, encodedSignature, encodedClientIV, encodedServerEncryptionKey, encodedECDHSenderKey, encodedECDSASenderKey, RequestedExpirationHours);
         var uploadResponse = await CrypterApiService.UploadFileTransferAsync(request, Recipient, UserSessionService.LoggedIn);
         uploadResponse.DoLeft(x =>
         {
            switch (x)
            {
               case UploadTransferError.BlockedByUserPrivacy:
                  ErrorMessages.Add("This user does not accept files.");
                  break;
               case UploadTransferError.OutOfSpace:
                  ErrorMessages.Add("The server is full. Try again later.");
                  break;
               default:
                  ErrorMessages.Add("An error occurred");
                  break;
            }
         });

         uploadResponse.DoRight(x =>
         {
            TransferId = x.Id;

            if (string.IsNullOrEmpty(Recipient))
            {
               ModalForAnonymousRecipient.Open();
            }
            else
            {
               ModalForUserRecipient.Open();
            }
         });

         Cleanup();
         EncryptionInProgress = false;
      }

      protected async Task<List<byte[]>> EncryptBytesAsync(IBrowserFile file, byte[] symmetricKey, byte[] symmetricIV)
      {
         await SetProgressBar(0.0);

         using var fileStream = file.OpenReadStream(MaxFileSizeBytes);

         int chunkCount = (int)Math.Ceiling(file.Size / (double)Base64SafeChunkSize);
         List<byte[]> ciphertextPartitions = new(chunkCount);

         await SimpleEncryptionService.EncryptChunkedAsync(symmetricKey, symmetricIV, fileStream, file.Size, Base64SafeChunkSize,
            async encryptedChunk =>
            {
               ciphertextPartitions.Insert(ciphertextPartitions.Count, encryptedChunk);
               await SetProgressBar(ciphertextPartitions.Count / (double)ciphertextPartitions.Capacity);
            });

         return ciphertextPartitions;
      }

      protected async Task<byte[]> SignBytesAsync(IBrowserFile file, PEMString ed25519PrivateKey)
      {
         await SetProgressBar(0.0);
         var ed25519PrivateDecoded = KeyConversion.ConvertEd25519PrivateKeyFromPEM(ed25519PrivateKey);
         var signer = new ECDSA();
         signer.InitializeSigner(ed25519PrivateDecoded);

         byte[] fileBytes = await ReadFileAsync(file);

         int processedBytes = 0;
         int chunkSize = (int)Math.Ceiling((double)fileBytes.Length / 100);
         while (processedBytes + chunkSize < fileBytes.Length)
         {
            var plaintextChunk = fileBytes[processedBytes..(processedBytes + chunkSize)];

            signer.SignerDigestChunk(plaintextChunk);

            processedBytes += chunkSize;
            await SetProgressBar((double)processedBytes / fileBytes.Length);
         }

         int bytesRemaining = fileBytes.Length - processedBytes;
         var finalPlaintextChunk = fileBytes[processedBytes..(processedBytes + bytesRemaining)];
         signer.SignerDigestChunk(finalPlaintextChunk);
         var signature = signer.GenerateSignature();
         await SetProgressBar(1.0);
         return signature;
      }

      private async Task<byte[]> ReadFileAsync(IBrowserFile file)
      {
         var fileSize = Convert.ToInt32(file.Size);
         byte[] plaintextBytes = new byte[fileSize];
         using var fileStream = file.OpenReadStream(MaxFileSizeBytes);

         int loadedFileBytes = 0;
         while (loadedFileBytes + Base64SafeChunkSize < fileSize)
         {
            loadedFileBytes += await fileStream.ReadAsync(plaintextBytes.AsMemory(loadedFileBytes, Base64SafeChunkSize));
         }

         int remainingBytesToRead = fileSize - loadedFileBytes;
         await fileStream.ReadAsync(plaintextBytes.AsMemory(loadedFileBytes, remainingBytesToRead));
         return plaintextBytes;
      }

      protected override void Cleanup()
      {
         SelectedFile = null;
         base.Cleanup();
      }

      protected async Task SetProgressBar(double percentComplete)
      {
         ShowProgressBar = true;
         ProgressPercent = percentComplete;
         StateHasChanged();
         await Task.Delay(5);
      }

      protected async Task HideEncryptionProgress()
      {
         ShowProgressBar = false;
         StateHasChanged();
         await Task.Delay(400);
      }
   }
}
