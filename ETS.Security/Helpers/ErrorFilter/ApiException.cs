using Microsoft.AspNetCore.Mvc;
using Microsoft.OpenApi.Expressions;

namespace ETS.Security.Helpers;

public class ApiException : Exception
{
    public int StatusCode { get; set; }
    public string Title { get; set; }
    public string Detail { get; set; }
    
}