using MatIdentity.Core.Users;

namespace MatIdentity.Tests;

/// <summary>The rules for a new password: long enough, not the name or the address, not one of those tried first.</summary>
public sealed class PasswordPolicyTests
{
    [Theory]
    [InlineData("short1", 8, "Use at least 8 characters.")]
    [InlineData("long-enough-but-12", 20, "Use at least 20 characters.")]
    [InlineData("Password123", 8, "This is one of the passwords tried first. Choose another one.")]
    [InlineData("anna-schmidt-2024", 8, "The password must not contain the user name or the e-mail address.")]
    [InlineData("xx-annas-mail-xx", 8, "The password must not contain the user name or the e-mail address.")]
    [InlineData("Blue-Kettle-Rain", 8, null)]
    public void A_new_password_follows_the_rules(string password, int minLength, string? error)
        => Assert.Equal(error, PasswordPolicy.Check(password, minLength, "anna-schmidt", "annas-mail@example.test"));

    [Fact]
    public void The_shortest_length_is_never_below_eight()
        => Assert.Equal("Use at least 8 characters.", PasswordPolicy.Check("1234567", 4));
}
