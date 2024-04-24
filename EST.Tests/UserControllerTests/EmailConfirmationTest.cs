using ETS.Security.Controllers;
using ETS.Security.DTOs;
using ETS.Security.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Moq;

namespace EST.Tests.UserControllerTests;

public class EmailConfirmationTest
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
    public async Task SuccessEmailVerificationTest()
    {
        //Arrange
        string id = Guid.NewGuid().ToString();
        string code = Guid.NewGuid().ToString();

        var expectedResponse = "http://localhost:4200/verification-success";

        _mockUserService.Setup(us => us.VerifyEmail(id, code)).ReturnsAsync(true);

        //Act
        var result = await _userController.EmailConfirmation(id, code);

        //Assert 
        _mockUserService.Verify(us => us.VerifyEmail(id, code), Times.Once());
        Assert.IsNotNull(result);
        Assert.IsInstanceOf<RedirectResult>(result);
        Assert.That(((RedirectResult)result).Url, Is.EqualTo(expectedResponse));
    }
    [Test]
    public async Task FailedVerifyEmailEmailVerificationTest()
    {
        string id = Guid.NewGuid().ToString();
        string code = Guid.NewGuid().ToString();
       

        var expectedResponse = "http://localhost:4200/verification-failure";

        _mockUserService.Setup(us => us.VerifyEmail(id, code)).ReturnsAsync(false);

        //Act
        var result = await _userController.EmailConfirmation(id, code);

        //Assert
        _mockUserService.Verify(us => us.VerifyEmail(id, code), Times.Once());
        Assert.IsNotNull(result);
        Assert.IsInstanceOf<RedirectResult>(result);
        Assert.That(((RedirectResult)result).Url, Is.EqualTo(expectedResponse));
    }
}