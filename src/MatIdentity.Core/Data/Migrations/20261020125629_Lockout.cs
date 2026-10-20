using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MatIdentity.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class Lockout : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "FailedSignIns",
                table: "User",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "LockedUntil",
                table: "User",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "FailedSignIns",
                table: "User");

            migrationBuilder.DropColumn(
                name: "LockedUntil",
                table: "User");
        }
    }
}
