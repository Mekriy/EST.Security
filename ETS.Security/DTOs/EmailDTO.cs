using System.ComponentModel.DataAnnotations;

namespace ETS.Security.DTOs
{
    public class EmailDTO
    {
        public string To { get; set; }
        public string Subject { get; set; }
    }
}
