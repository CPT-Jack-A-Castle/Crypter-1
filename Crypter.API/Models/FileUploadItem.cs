﻿using System;
using System.Data;
using System.Threading.Tasks;
using MySqlConnector;
using Crypter.API.Controllers;

namespace CrypterAPI.Models
{
    // FileUpload inherits from UploadItem
    public class FileUploadItem : UploadItem
    {
        public string EncryptedFileContentPath { get; set; }

        //constructor sets TimeStamp upon instantiation
        public FileUploadItem()
        {
            Created = DateTime.UtcNow;
            ExpirationDate = DateTime.UtcNow.AddHours(24);
        }
 
        public async Task InsertAsync(CrypterDB db, string baseSaveDirectory)
        {
            using var cmd = db.Connection.CreateCommand();
            //guid as unique identifier
            ID = Guid.NewGuid().ToString();
            // Create file paths and insert these paths
            FilePaths filePath = new FilePaths(baseSaveDirectory);
            var success = filePath.SaveFile(UntrustedName, ID, true);
            EncryptedFileContentPath = filePath.ActualPathString;
            Signature = filePath.SigPathString;
            cmd.CommandText = @"INSERT INTO `FileUploads` (`ID`,`UserID`,`UntrustedName`,`Size`, `Signature`, `Created`, `ExpirationDate`, `EncryptedFileContentPath`) VALUES (@id, @userid, @untrustedname, @size, @signature, @created, @expirationdate, @encryptedfilecontentpath);";
            BindParams(cmd);
            await cmd.ExecuteNonQueryAsync();
        }

        public async Task UpdateAsync(CrypterDB db)
        {
            using var cmd = db.Connection.CreateCommand();
            cmd.CommandText = @"UPDATE `FileUploads` SET `UserID` = @userid, `UntrustedName` = @untrustedname, `Size` = @size, `Signature` = @signature, `Created` = @created, `ExpirationDate` = @expirationdate, `EncryptedFileContentPath`= @encryptedfilecontentpath WHERE `ID` = @id;";
            BindParams(cmd);
            //BindId(cmd);
            await cmd.ExecuteNonQueryAsync();
        }

        public async Task DeleteAsync(CrypterDB db)
        {
            using var cmd = db.Connection.CreateCommand();
            cmd.CommandText = @"DELETE FROM `FileUploads` WHERE `ID` = @id;";
            BindId(cmd);
            await cmd.ExecuteNonQueryAsync();
        }

        private void BindId(MySqlCommand cmd)
        {
            cmd.Parameters.Add(new MySqlParameter
            {
                ParameterName = "@id",
                DbType = DbType.String,
                Value = ID,
            });
        }

        private void BindParams(MySqlCommand cmd)
        {
            cmd.Parameters.Add(new MySqlParameter
            {
                ParameterName = "@id",
                DbType = DbType.String,
                Value = ID
            });
            cmd.Parameters.Add(new MySqlParameter
            {
                ParameterName = "@userid",
                DbType = DbType.String,
                Value = UserID,
            });
            cmd.Parameters.Add(new MySqlParameter
            {
                ParameterName = "@untrustedname",
                DbType = DbType.String,
                Value = UntrustedName,
            });
            cmd.Parameters.Add(new MySqlParameter
            {
                ParameterName = "@size",
                DbType = DbType.Int16,
                Value = Size,
            });
            cmd.Parameters.Add(new MySqlParameter
            {
                ParameterName = "@signature",
                DbType = DbType.String,
                Value = Signature,
            });
            cmd.Parameters.Add(new MySqlParameter
            {
                ParameterName = "@created",
                DbType = DbType.String,
                Value = Created,
            });
            cmd.Parameters.Add(new MySqlParameter
            {
                ParameterName = "@expirationdate",
                DbType = DbType.String,
                Value = ExpirationDate,
            });
            cmd.Parameters.Add(new MySqlParameter
            {
                ParameterName = "@encryptedfilecontentpath",
                DbType = DbType.String,
                Value = EncryptedFileContentPath,
            });
        }
    }
}