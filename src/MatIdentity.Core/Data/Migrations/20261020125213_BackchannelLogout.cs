using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MatIdentity.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class BackchannelLogout : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ClientIds",
                table: "UserSession",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ClientIds",
                table: "UserSession");
        }
    }
}
