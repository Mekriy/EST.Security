namespace ETS.Security
{
    public class ConstantVariables
    {
        public static string ngrok = "https://be62-178-212-241-227.ngrok-free.app";
        public static string htmlSuccessVerification = @"<!DOCTYPE html>
<html>
<head>
    <title>Email Verification</title>
    <link rel=""preconnect"" href=""https://fonts.googleapis.com"">
    <link rel=""preconnect"" href=""https://fonts.gstatic.com"" crossorigin>
    <link href=""https://fonts.googleapis.com/css2?family=Roboto:ital,wght@0,100;0,300;0,400;0,500;0,700;0,900;1,100;1,300;1,400;1,500;1,700;1,900&display=swap"" rel=""stylesheet"">   
    <style>
         .body-text{
        font-family: 'Roboto';
        border-radius: 15px;
        padding: 10px;
    }
    </style>
</head>
<body class=""body-text"">
    <div class=""main-div"">
        <h1>Email Verified Successfully!</h1>
        <p>Your email has been successfully verified.</p>
        <p>Thanks for using our service</p>
    </div>
</body>
</html>
        ";
        public static string htmlFailVerification = @"<!DOCTYPE html>
<html>
<head>
    <title>Email Verification</title>
    <link rel=""preconnect"" href=""https://fonts.googleapis.com"">
    <link rel=""preconnect"" href=""https://fonts.gstatic.com"" crossorigin>
    <link href=""https://fonts.googleapis.com/css2?family=Roboto:ital,wght@0,100;0,300;0,400;0,500;0,700;0,900;1,100;1,300;1,400;1,500;1,700;1,900&display=swap"" rel=""stylesheet"">   
    <style>
         .body-text{
        font-family: 'Roboto';
        border-radius: 15px;
        padding: 10px;
    }
    </style>
</head>
<body class=""body-text"">
    <div class=""main-div"">
        <h1>Email verification failed!</h1>
        <p>Something went wrong while confirming email.</p>
        <p>Please try again later.</p>
    </div>
</body>
</html>
        ";
    }
}
