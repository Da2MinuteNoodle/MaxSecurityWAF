using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MaxSecurityWAF.Migrations
{
    /// <inheritdoc />
    public partial class PasswordHashing : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "Users",
                keyColumn: "UserId",
                keyValue: -1,
                column: "Password",
                value: "P4geAuE2yX/PDRHuJSq74FF5vO782rWz5c0LAQPR8m45DEYAONhu1wYnAn60PSNyjocqEBdnCeKCJfK3sKyuWw==");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "Users",
                keyColumn: "UserId",
                keyValue: -1,
                column: "Password",
                value: "admin");
        }
    }
}
