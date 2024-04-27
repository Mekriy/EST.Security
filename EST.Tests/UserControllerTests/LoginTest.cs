using ETS.Security.Controllers;
using ETS.Security.DTOs;
using ETS.Security.Helpers;
using ETS.Security.Interfaces;
using ETS.Security.Services.Authentication;
using Microsoft.AspNetCore.Mvc;
using Moq;

namespace EST.Tests.UserControllerTests;

public class LoginTest
{
    private Mock<IUserService> _mockUserService;
    private UserController _userController;
    [SetUp]
    public void SetUp()
    {
        _mockUserService = new Mock<IUserService>();
        _userController = new UserController(_mockUserService.Object);
    }

    [TearDown]
    public void TearDown()
    {
        _userController = null;
    }
    [Test] 
    public async Task SuccessLoginTest()
    {
        //Arrange
        var userDTO = new UserLoginDTO()
        {
            Email = "test@gmail.com",
            Password = "Usa12#s!Pass",
        };

        var token = new AuthenticatedUserResponse
        {
            Access = "dB_8.C4f-3.1KwL",
        };

        _mockUserService.Setup(us => us.Login(userDTO)).ReturnsAsync(token);

        //Act
        var result = await _userController.Login(userDTO);

        //Assert
        _mockUserService.Verify(us => us.Login(userDTO), Times.Once);

        Assert.IsNotNull(result);
        Assert.IsInstanceOf<ObjectResult>(result);
        Assert.That((result as ObjectResult)!.Value, Is.EqualTo(token));
    }
    [Test] 
    public async Task FailedCheckPasswordsLoginTest()
    {
        //Arrange
        var userDTO = new UserLoginDTO()
        {
            Email = "test@gmail.com",
            Password = "Usa12#s!Pass",
        };

        _mockUserService.Setup(us => us.Login(userDTO)).ThrowsAsync(new ApiException());

        //Act
        Assert.ThrowsAsync<ApiException>(async () => await _userController.Login(userDTO));
        //Assert
        _mockUserService.Verify(us => us.Login(userDTO), Times.Once);
    }
}