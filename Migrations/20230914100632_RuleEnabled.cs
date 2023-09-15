using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MaxSecurityWAF.Migrations
{
    /// <inheritdoc />
    public partial class RuleEnabled : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "Enabled",
                table: "Rules",
                type: "INTEGER",
                nullable: false,
                defaultValue: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Enabled",
                table: "Rules");
        }
    }
}
