﻿using Crypter.Console.Jobs;
using Crypter.Core;
using Crypter.Core.Interfaces;
using Crypter.Core.Models;
using Crypter.Core.Services.DataAccess;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Crypter.Console
{
   public class Program
   {
      public static async Task<int> Main(string[] args)
      {
         IConfiguration configuration = new ConfigurationBuilder()
               .AddJsonFile("appsettings.json")
               .Build();

         var serviceProvider = new ServiceCollection()
            .AddLogging(configure => configure.AddConsole())
            .AddSingleton(configuration)
            .AddSingleton<DataContext>()
            .AddSingleton<IBaseTransferService<MessageTransfer>, MessageTransferItemService>()
            .AddSingleton<IBaseTransferService<FileTransfer>, FileTransferItemService>()
            .AddSingleton<IUserPrivacySetting, UserPrivacySetting>()
            .AddSingleton<IUserProfileService, UserProfileService>()
            .AddSingleton<IUserSearchService, UserSearchService>()
            .AddSingleton<IUserService, UserService>()
            .BuildServiceProvider();

         if (args == null || args.Length == 0 || HelpRequired(args[0]))
         {
            Help.DisplayHelp();
            return 0;
         }

         if (RequestDeleteExpired(args[0]))
         {
            var deleteJob = new DeleteExpired(configuration["EncryptedFileStore"],
               serviceProvider.GetService<IBaseTransferService<MessageTransfer>>(),
               serviceProvider.GetService<IBaseTransferService<FileTransfer>>(),
               serviceProvider.GetService<ILogger<DeleteExpired>>());

            await deleteJob.RunAsync();
            return 0;
         }

         if (RequestCreateCrypterSchema(args[0]))
         {
            if (args.Length < 2)
            {
               System.Console.WriteLine("This command requires a connection string as the second argument");
               return -2;
            }
            var connectionString = args[1];
            var schemaManager = new ManageSchema(connectionString);
            await schemaManager.CreateSchemaAsync();
            return 0;
         }

         if (RequestInitialCrypterMigration(args[0]))
         {
            if (args.Length < 2)
            {
               System.Console.WriteLine("This command requires a connection string as the second argument");
               return -2;
            }

            var connectionString = args[1];
            var schemaManager = new ManageSchema(connectionString);
            await schemaManager.PerformInitialMigration();
            return 0;
         }

         if (RequestDeleteCrypterSchema(args[0]))
         {
            if (args.Length < 2)
            {
               System.Console.WriteLine("This command requires a connection string as the second argument");
               return -2;
            }

            var confirmationText = "NUKE THE DATABASE";
            System.Console.Write($"Enter '{confirmationText}' to proceed with database deletion. Enter anything else to cancel: ");
            if (System.Console.ReadLine() != confirmationText)
            {
               System.Console.WriteLine("Standing down");
               return 0;
            }

            var connectionString = args[1];
            var schemaManager = new ManageSchema(connectionString);
            await schemaManager.DeleteSchemaAsync();
            return 0;
         }

         if (RequestDeleteUser(args[0]))
         {
            if (args.Length < 2)
            {
               System.Console.WriteLine("This command requires a username string as the second argument");
               return -2;
            }

            string username = args[1];
            var deleteUser = new DeleteUser(serviceProvider.GetService<IUserService>());
            if (!await deleteUser.RunAsync(username))
            {
               System.Console.WriteLine($"The Username \"{username}\" does not exist.");
            }
            return 0;            
         }

         Help.DisplayHelp();
         return -1;
      }

      private static bool HelpRequired(string param)
      {
         return param == "-h" || param == "--help" || param == "/?";
      }

      private static bool RequestDeleteExpired(string param)
      {
         return param == "-d" || param == "--delete-expired";
      }

      private static bool RequestCreateCrypterSchema(string param)
      {
         return param == "--create-schema";
      }

      private static bool RequestInitialCrypterMigration(string param)
      {
         return param == "--migrate-schema-v1";
      }

      private static bool RequestDeleteCrypterSchema(string param)
      {
         return param == "--delete-schema";
      }
      private static bool RequestDeleteUser(string param)
      {
         return param == "--delete-user";
      }
    }
}
