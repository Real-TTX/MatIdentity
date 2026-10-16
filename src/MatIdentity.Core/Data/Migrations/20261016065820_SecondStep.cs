using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MatIdentity.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class SecondStep : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RecoveryCodeHashes",
                table: "User",
                type: "TEXT",
                maxLength: 1000,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "TotpEnabled",
                table: "User",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<long>(
                name: "TotpLastStep",
                table: "User",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<string>(
                name: "TotpSecret",
                table: "User",
                type: "TEXT",
                maxLength: 1000,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "Passkey",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    UserId = table.Column<long>(type: "INTEGER", nullable: false),
                    CredentialId = table.Column<string>(type: "TEXT", maxLength: 1400, nullable: false),
                    PublicKey = table.Column<byte[]>(type: "BLOB", nullable: false),
                    SignCount = table.Column<long>(type: "INTEGER", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    AaGuid = table.Column<Guid>(type: "TEXT", nullable: false),
                    LastUsedAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CreateDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CreateUserId = table.Column<long>(type: "INTEGER", nullable: true),
                    UpdateDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdateUserId = table.Column<long>(type: "INTEGER", nullable: true),
                    UpdateState = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Passkey", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Passkey_User_UserId",
                        column: x => x.UserId,
                        principalTable: "User",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Passkey_CredentialId",
                table: "Passkey",
                column: "CredentialId",
                unique: true,
                filter: "\"UpdateState\" <> 0");

            migrationBuilder.CreateIndex(
                name: "IX_Passkey_UserId",
                table: "Passkey",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Passkey");

            migrationBuilder.DropColumn(
                name: "RecoveryCodeHashes",
                table: "User");

            migrationBuilder.DropColumn(
                name: "TotpEnabled",
                table: "User");

            migrationBuilder.DropColumn(
                name: "TotpLastStep",
                table: "User");

            migrationBuilder.DropColumn(
                name: "TotpSecret",
                table: "User");
        }
    }
}
