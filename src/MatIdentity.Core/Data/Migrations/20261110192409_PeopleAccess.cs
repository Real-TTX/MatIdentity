using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MatIdentity.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class PeopleAccess : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ExternalId",
                table: "User",
                type: "TEXT",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ExternalId",
                table: "Group",
                type: "TEXT",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Permissions",
                table: "AppGrant",
                type: "TEXT",
                maxLength: 4000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Quotas",
                table: "AppGrant",
                type: "TEXT",
                maxLength: 4000,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "AppPermission",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ClientId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Key = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Label = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Hint = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                    Roles = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    SortOrder = table.Column<int>(type: "INTEGER", nullable: false),
                    CreateDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CreateUserId = table.Column<long>(type: "INTEGER", nullable: true),
                    UpdateDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdateUserId = table.Column<long>(type: "INTEGER", nullable: true),
                    UpdateState = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AppPermission", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AppQuota",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ClientId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Key = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Label = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Unit = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    Period = table.Column<string>(type: "TEXT", maxLength: 16, nullable: true),
                    Min = table.Column<long>(type: "INTEGER", nullable: true),
                    Max = table.Column<long>(type: "INTEGER", nullable: true),
                    Hint = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                    SortOrder = table.Column<int>(type: "INTEGER", nullable: false),
                    CreateDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CreateUserId = table.Column<long>(type: "INTEGER", nullable: true),
                    UpdateDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdateUserId = table.Column<long>(type: "INTEGER", nullable: true),
                    UpdateState = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AppQuota", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AppPermission_ClientId_Key",
                table: "AppPermission",
                columns: new[] { "ClientId", "Key" },
                unique: true,
                filter: "\"UpdateState\" <> 0");

            migrationBuilder.CreateIndex(
                name: "IX_AppQuota_ClientId_Key",
                table: "AppQuota",
                columns: new[] { "ClientId", "Key" },
                unique: true,
                filter: "\"UpdateState\" <> 0");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AppPermission");

            migrationBuilder.DropTable(
                name: "AppQuota");

            migrationBuilder.DropColumn(
                name: "ExternalId",
                table: "User");

            migrationBuilder.DropColumn(
                name: "ExternalId",
                table: "Group");

            migrationBuilder.DropColumn(
                name: "Permissions",
                table: "AppGrant");

            migrationBuilder.DropColumn(
                name: "Quotas",
                table: "AppGrant");
        }
    }
}
