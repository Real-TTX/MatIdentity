using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MatIdentity.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class ClientBranding : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ClientBranding",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ClientId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 60, nullable: false),
                    Accent = table.Column<string>(type: "TEXT", maxLength: 7, nullable: true),
                    HideIdentity = table.Column<bool>(type: "INTEGER", nullable: false),
                    LogoContentType = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    Logo = table.Column<byte[]>(type: "BLOB", nullable: true),
                    LogoHash = table.Column<string>(type: "TEXT", maxLength: 16, nullable: true),
                    BackgroundContentType = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    Background = table.Column<byte[]>(type: "BLOB", nullable: true),
                    BackgroundHash = table.Column<string>(type: "TEXT", maxLength: 16, nullable: true),
                    CreateDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CreateUserId = table.Column<long>(type: "INTEGER", nullable: true),
                    UpdateDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdateUserId = table.Column<long>(type: "INTEGER", nullable: true),
                    UpdateState = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientBranding", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ClientBranding_ClientId",
                table: "ClientBranding",
                column: "ClientId",
                unique: true,
                filter: "\"UpdateState\" <> 0");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ClientBranding");
        }
    }
}
