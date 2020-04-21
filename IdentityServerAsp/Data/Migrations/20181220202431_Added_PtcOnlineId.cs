using Microsoft.EntityFrameworkCore.Migrations;

namespace IdentityServerAsp.Data.Migrations
{
    public partial class Added_PtcOnlineId : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ptcOnlineId",
                table: "AspNetUsers",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ptcOnlineId",
                table: "AspNetUsers");
        }
    }
}
