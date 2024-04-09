using ETS.Security.Controllers;
using ETS.Security.DTOs;
using ETS.Security.Interfaces;
using ETS.Security.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EST.Tests.UserControllerTests
{
    public class RegisterUserTest
    {
        private Mock<IUserService> _mockUserService;
        private UserController _userController;
        [SetUp]
        public void Setup()
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
        public async Task RegisterUserSuccess()
        {
            // Arrange
            var userDto = new UserRegisterDTO
            {
                UserName = "TestName",
                Email = "TestEmail@gmail.com",
                Password = "testpassword123!S"
            };
            _mockUserService.Setup(x => x.Create(It.IsAny<UserRegisterDTO>())).ReturnsAsync(true);

            // Act
            var result = await _userController.Register(userDto);

            // Assert
            _mockUserService.Verify(x => x.Create(userDto), Times.Once);
            Assert.IsNotNull(result);
            Assert.IsInstanceOf<CreatedResult>(result);
            //Assert.That((result as CreatedResult)!.Value, Is.EqualTo("/api/User", It.IsAny<UserDTO>()));
        }
        [Test]
        public async Task RegisterUserFail()
        {
            // Arrange
            var userDto = new UserRegisterDTO
            {
                UserName = "TestName",
                Email = "TestEmail@gmail.com",
                Password = "testpassword123!S"
            };

            _mockUserService
                .Setup(t => t.Create(It.IsAny<UserRegisterDTO>()))
                .ThrowsAsync(new Exception("Error creating user"));

            // Act
            var result = await _userController.Register(userDto);

            // Assert
            _mockUserService.Verify(x => x.Create(userDto), Times.Once);
            Assert.IsNotNull(result);
            Assert.IsInstanceOf<Exception>(result);
            Assert.That((result as Exception)!.Message, Is.EqualTo("Error creating user"));
        }
    }
}
