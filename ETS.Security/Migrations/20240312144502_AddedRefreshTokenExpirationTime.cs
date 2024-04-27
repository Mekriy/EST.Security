using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ETS.Security.Migrations
{
    public partial class AddedRefreshTokenExpirationTime : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "ExpirationTime",
                table: "AspNetUsers",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ExpirationTime",
                table: "AspNetUsers");
        }
    }
}
