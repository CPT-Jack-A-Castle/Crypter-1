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

using Crypter.Common.Monads;
using Crypter.Common.Primitives;
using MediatR;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Crypter.Core.Features.Transfer.Commands
{
   public class InsertAnonymousMessageTransferCommand : IRequest<bool>
   {
      public Maybe<Guid> SenderId { get; init; }
      public Maybe<Guid> RecipientId { get; init; }
      public string Subject { get; init; }
      public Base64String Ciphertext { get; init; }
      public Base64String DigitalSignature { get; init; }
      public Base64String DigitalSignaturePublicKey { get; init; }
      public Base64String DiffieHellmanPublicKey { get; init; }
      public Base64String RecipientProof { get; init; }
      public int RequestedLifetimeHours { get; init; }

      public InsertAnonymousMessageTransferCommand(
         Maybe<Guid> senderId,
         Maybe<Guid> recipientId,
         string subject,
         Base64String ciphertext,
         Base64String digitalSignature,
         Base64String digitalSignaturePublicKey,
         Base64String diffieHellmandPublicKey,
         Base64String recipientProof,
         int requestedLifetimeHours)
      {
         SenderId = senderId;
         RecipientId = recipientId;
         Subject = subject;
         Ciphertext = ciphertext;
         DigitalSignature = digitalSignature;
         DigitalSignaturePublicKey = digitalSignaturePublicKey;
         DiffieHellmanPublicKey = diffieHellmandPublicKey;
         RecipientProof = recipientProof;
         RequestedLifetimeHours = requestedLifetimeHours;
      }

      public static 
   }

   public class InsertAnonymousMessageTransferCommandHandler : IRequestHandler<InsertAnonymousMessageTransferCommand, bool>
   {
      public InsertAnonymousMessageTransferCommandHandler()
      { }

      public async Task<bool> Handle(InsertAnonymousMessageTransferCommand request, CancellationToken cancellationToken)
      {

      }
   }
}
