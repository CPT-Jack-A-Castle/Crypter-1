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

using Crypter.Contracts.Features.User.GetReceivedTransfers;
using MediatR;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Crypter.Core.Features.User.Queries
{
   public class UserReceivedMessagesQuery : IRequest<List<UserReceivedMessageDTO>>
   {
      public Guid UserId { get; init; }

      public UserReceivedMessagesQuery(Guid userId)
      {
         UserId = userId;
      }
   }

   public class UserReceivedMessagesQueryHandler : IRequestHandler<UserReceivedMessagesQuery, List<UserReceivedMessageDTO>>
   {
      private readonly DataContext _context;

      public UserReceivedMessagesQueryHandler(DataContext context)
      {
         _context = context;
      }

      public async Task<List<UserReceivedMessageDTO>> Handle(UserReceivedMessagesQuery request, CancellationToken cancellationToken)
      {
         return await _context.UserMessageTransfers
            .Where(x => x.RecipientId == request.UserId)
            .Select(x => new UserReceivedMessageDTO(x.Id, x.Subject, x.Sender.Username, x.Sender.Profile.Alias, x.Expiration))
            .ToListAsync(cancellationToken);
      }
   }
}
