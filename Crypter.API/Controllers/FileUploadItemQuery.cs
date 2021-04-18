﻿using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Threading.Tasks;
using MySqlConnector;
using CrypterAPI.Models;

namespace CrypterAPI.Controllers
{
    public class FileUploadItemQuery
    {
        public CrypterDB Db { get; }
        public FileUploadItemQuery(CrypterDB db)
        {
            Db = db;
        }

        public async Task<FileUploadItem> FindOneAsync(string id)
        {
            using var cmd = Db.Connection.CreateCommand();
            cmd.CommandText = @"SELECT `ID`, `UserID`, `UntrustedName`, `Size`,`EncryptedFileContentPath`,`Signature`,`Created`, `ExpirationDate` FROM `FileUploads` WHERE `ID` = @id";
            cmd.Parameters.Add(new MySqlParameter
            {
                ParameterName = "@id",
                DbType = DbType.String,
                Value = id,
            });
            var result = await ReadAllAsync(await cmd.ExecuteReaderAsync());
            return result.Count > 0 ? result[0] : null;
        }

        public async Task<List<FileUploadItem>> LatestItemsAsync()
        {
            using var cmd = Db.Connection.CreateCommand();
            cmd.CommandText = @"SELECT `ID`, `UserID`, `UntrustedName`, `Size`,`EncryptedFileContentPath`,`Signature`,`Created`, `ExpirationDate` FROM `FileUploads`";
            return await ReadAllAsync(await cmd.ExecuteReaderAsync());
        }

        public async Task DeleteAllAsync()
        {
            using var txn = await Db.Connection.BeginTransactionAsync();
            using var cmd = Db.Connection.CreateCommand();
            cmd.CommandText = @"DELETE FROM `FileUploads`";
            //added per https://fl.vu/mysql-trans
            cmd.Transaction = txn;
            await cmd.ExecuteNonQueryAsync();
            await txn.CommitAsync();
        }

        private async Task<List<FileUploadItem>> ReadAllAsync(DbDataReader reader)
        {
            var items = new List<FileUploadItem>();
            using (reader)
            {
                while (await reader.ReadAsync())
                {
                    var item = new FileUploadItem()
                    {
                        ID = reader.GetString(0),
                        UserID = reader.GetString(1),
                        UntrustedName = reader.GetString(2),
                        Size = reader.GetInt32(3),
                        EncryptedFileContentPath = reader.GetString(4),
                        Signature = reader.GetString(5),
                        Created = reader.GetDateTime(6),
                        ExpirationDate = reader.GetDateTime(7)
                    };
                    items.Add(item);
                }
            }
            return items;
        }
    }
}