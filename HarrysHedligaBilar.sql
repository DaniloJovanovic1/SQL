

IF EXISTS (SELECT * FROM sys.databases WHERE name = 'HarysHedligBilar')
BEGIN
    DROP DATABASE HarysHedligBilar;
END

CREATE DATABASE HarysHedligBilar;
GO

USE HarysHedligBilar;
GO

CREATE SCHEMA hhb;
GO


CREATE TABLE hhb.Roles ( 
  RoleID INT IDENTITY(1,1) PRIMARY KEY,
  RoleName NVARCHAR(50) NOT NULL UNIQUE
);

INSERT INTO hhb.Roles (RoleName)
VALUES ('Customer'), ('Admin');
GO


CREATE TABLE hhb.Users( 
  UserID INT IDENTITY(1,1) PRIMARY KEY,                               
  UserName NVARCHAR(50) NOT NULL UNIQUE,
  Email NVARCHAR(50) NOT NULL UNIQUE,
  PasswordHash VARBINARY(64) NOT NULL,
  PasswordSalt NVARCHAR(50) NOT NULL,
  FirstName NVARCHAR(50) NOT NULL,
  LastName NVARCHAR(50) NOT NULL,
  Street NVARCHAR(100) NOT NULL,
  Zip NVARCHAR(20) NOT NULL,
  City NVARCHAR(50) NOT NULL,
  Country NVARCHAR(50) NOT NULL,
  PhoneNumber NVARCHAR(50) NOT NULL,
  IpAdress NVARCHAR(50) NOT NULL,
  IsVerified BIT DEFAULT 0 NOT NULL,
  IsLocked BIT DEFAULT 0 NOT NULL,
  VerificationCode NVARCHAR(50) NULL,
  VerificationExpiry DATETIME NULL,
  CreatedAt DATETIME DEFAULT GETDATE() NOT NULL,
  RoleID INT DEFAULT 1 NOT NULL,
  FOREIGN KEY (RoleID) REFERENCES hhb.Roles(RoleID)
);
GO


DECLARE @Salt1 NVARCHAR(50) = CONVERT(NVARCHAR(50), NEWID());
DECLARE @Hash1 VARBINARY(64) = HASHBYTES('SHA2_512', 'serbien123' + @Salt1);

INSERT INTO hhb.Users (UserName, Email, PasswordHash, PasswordSalt, FirstName, LastName, Street, Zip, City, 
    Country, PhoneNumber, IpAdress, IsVerified, IsLocked, VerificationCode, VerificationExpiry, CreatedAt, RoleID)
VALUES ('Danilo', 'danilo@gmail.com', @Hash1, @Salt1, 
    'Danilo', 'Jovanovic', 'Main Street 123', '12345', 'Stockholm',
    'Sweden', '+46701234567', '192.168.1.1', 1, 0, NULL, NULL, GETDATE(), 1);

DECLARE @Salt2 NVARCHAR(50) = CONVERT(NVARCHAR(50), NEWID());
DECLARE @Hash2 VARBINARY(64) = HASHBYTES('SHA2_512', 'hejhej123' + @Salt2);

INSERT INTO hhb.Users (UserName, Email, PasswordHash, PasswordSalt, FirstName, LastName, Street, Zip, City, 
    Country, PhoneNumber, IpAdress, IsVerified, IsLocked, VerificationCode, VerificationExpiry, CreatedAt, RoleID)
VALUES ('Alex', 'alex@gmail.com', @Hash2, @Salt2, 
    'Alex', 'Tesfay', 'Baker Street 221B', '54321', 'Gothenburg',
    'Sweden', '+46707654321', '192.168.1.2', 0, 0, NULL, NULL, GETDATE(), 2);
GO


CREATE TABLE hhb.LoginAttempts (
  AttemptID INT IDENTITY(1,1) PRIMARY KEY,
  UserID INT NULL,
  FOREIGN KEY (UserID) REFERENCES hhb.Users(UserID),
  IpAdress NVARCHAR(50) NOT NULL,
  TimeAttempt DATETIME DEFAULT GETDATE() NOT NULL,
  Success BIT NOT NULL 
);

INSERT INTO hhb.LoginAttempts (UserID, IpAdress, Success)
  VALUES (1, '192.168.1.1', 1), 
       (1, '192.168.1.1', 0),  
       (1, '192.168.1.1', 1), 
	   (2,'192.168.1.2',1),
	   (2,'192.168.1.2',1),
	   (2,'192.168.1.2',0);
GO


CREATE TABLE hhb.PasswordReset (
  PasswordResetID INT IDENTITY(1,1) PRIMARY KEY,
  UserID INT NOT NULL,
  FOREIGN KEY (UserID) REFERENCES hhb.Users(UserID),
  ResetCode NVARCHAR(50) NOT NULL,
  CreatedAt DATETIME DEFAULT GETDATE() NOT NULL,
  ExpiresAt DATETIME NOT NULL,
  IsUsed BIT NOT NULL 
);
GO


CREATE OR ALTER PROCEDURE TryLogin 
    @Email NVARCHAR(50),
    @Password NVARCHAR(50),
    @IpAdress NVARCHAR(50)
AS
BEGIN 
    DECLARE @UserID INT;
    DECLARE @StoredPasswordHash VARBINARY(64);
    DECLARE @StoredSalt NVARCHAR(50);
    DECLARE @IsVerified BIT;
    DECLARE @IsLocked BIT;
    DECLARE @FailedAttempts INT;
    DECLARE @CurrentTime DATETIME = GETDATE();

	CREATE TABLE #TempLoginLog( 
	AttemptID INT IDENTITY(1,1) PRIMARY KEY,
    UserID INT NULL,
    IpAdress NVARCHAR(50) NOT NULL,
    TimeAttempt DATETIME DEFAULT GETDATE() NOT NULL,
    Success BIT NOT NULL 
);
	 

   
    SELECT @UserID = UserID,
           @StoredPasswordHash = PasswordHash,
           @StoredSalt = PasswordSalt,
           @IsVerified = IsVerified,
           @IsLocked = IsLocked
    FROM hhb.Users
    WHERE Email = @Email;

   
    IF @IsVerified != 1 
    BEGIN
        INSERT INTO hhb.LoginAttempts (UserID, IpAdress, TimeAttempt, Success)
        VALUES (NULL, @IpAdress, @CurrentTime, 0);

		INSERT INTO #TempLoginLog (UserID, IpAdress, TimeAttempt, Success)
        VALUES (NULL, @IpAdress, @CurrentTime, 0);

        SELECT 'Fel: Användaren är ej verifierad' AS Message;
        RETURN;
    END

   
    IF @UserID IS NULL
    BEGIN
        INSERT INTO hhb.LoginAttempts (UserID, IpAdress, TimeAttempt, Success)
        VALUES (NULL, @IpAdress, @CurrentTime, 0);

		INSERT INTO #TempLoginLog (UserID, IpAdress, TimeAttempt, Success)
        VALUES (NULL, @IpAdress, @CurrentTime, 0);

        SELECT 'Fel: Användaren existerar ej' AS Message;
        RETURN;
    END

    
    IF @IsLocked = 1
    BEGIN
        INSERT INTO hhb.LoginAttempts (UserID, IpAdress, TimeAttempt, Success)
        VALUES (@UserID, @IpAdress, @CurrentTime, 0);

		INSERT INTO #TempLoginLog (UserID, IpAdress, TimeAttempt, Success)
        VALUES (@UserID, @IpAdress, @CurrentTime, 0);


        SELECT 'Fel: Kontot är låst' AS Message;
        RETURN;
    END

    
    SELECT @FailedAttempts = COUNT(*)
    FROM hhb.LoginAttempts
    WHERE UserID = @UserID 
      AND Success = 0
      AND TimeAttempt >= DATEADD(MINUTE, -15, @CurrentTime);

  
    IF @FailedAttempts >= 3
    BEGIN
        UPDATE hhb.Users SET IsLocked = 1 WHERE UserID = @UserID;

        INSERT INTO hhb.LoginAttempts (UserID, IpAdress, TimeAttempt, Success)
        VALUES (@UserID, @IpAdress, @CurrentTime, 0);

		INSERT INTO #TempLoginLog (UserID, IpAdress, TimeAttempt, Success)
        VALUES (@UserID, @IpAdress, @CurrentTime, 0);

        SELECT 'Fel: För många misslyckade försök, kontot är nu låst' AS Message;
        RETURN;
    END

   
    IF @StoredPasswordHash <> HASHBYTES('SHA2_512', @Password + @StoredSalt)
    BEGIN 
        INSERT INTO hhb.LoginAttempts (UserID, IpAdress, TimeAttempt, Success)
        VALUES (@UserID, @IpAdress, @CurrentTime, 0);

		INSERT INTO #TempLoginLog (UserID, IpAdress, TimeAttempt, Success)
        VALUES (@UserID, @IpAdress, @CurrentTime, 0);


        SELECT 'Fel: Felaktigt lösenord' AS Message;
        RETURN;
    END

    
    INSERT INTO hhb.LoginAttempts (UserID, IpAdress, TimeAttempt, Success)
    VALUES (@UserID, @IpAdress, @CurrentTime, 1);

	INSERT INTO #TempLoginLog (UserID, IpAdress, TimeAttempt, Success)
    VALUES (@UserID, @IpAdress, @CurrentTime, 1);

    SELECT 'Inloggningen lyckades' AS Message;
END
GO

--
EXEC TryLogin 
      @Email = 'danilo@gmail.com',
      @Password = 'serbien123',
      @IpAdress = '192.168.1.1';
GO


GO

CREATE OR ALTER PROCEDURE ForgotPassword
    @Email NVARCHAR(50),
    @ResetResult NVARCHAR(50) OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @UserID INT;
    DECLARE @ResetToken NVARCHAR(50);
    DECLARE @ExpiryTime DATETIME;

   
    SELECT @UserID = UserID FROM hhb.Users WHERE Email = @Email;

    
    IF @UserID IS NULL
    BEGIN 
        SET @ResetResult = 'Fel: Ingen användare med denna e-postadress';
        RETURN;  
    END;

   
    IF EXISTS (SELECT 1 FROM hhb.PasswordReset WHERE UserID = @UserID AND IsUsed = 0 AND ExpiresAt > GETDATE())
    BEGIN
        SET @ResetResult = 'Fel: En återställningstoken finns redan';
        RETURN;
    END;

  
    DELETE FROM hhb.PasswordReset WHERE UserID = @UserID;

    
    SET @ResetToken = CONVERT(NVARCHAR(50), NEWID());
    SET @ExpiryTime = DATEADD(HOUR, 24, GETDATE());

    
    INSERT INTO hhb.PasswordReset (UserID, ResetCode, CreatedAt, ExpiresAt, IsUsed)
    VALUES (@UserID, @ResetToken, GETDATE(), @ExpiryTime, 0);

    
   SELECT @ResetToken AS ResetToken, @ResetResult AS Message;
END;
GO
GO

--Använd ResetToken för att byta lösenord i SP: SetForgetenPassword
--Restetoken kommer även lagras och kunna hittas i PasswordResetTabellen

DECLARE @Result NVARCHAR(50);
EXEC ForgotPassword
@Email = 'danilo@gmail.com', 
@ResetResult = @Result OUTPUT;
PRINT @Result;

GO

CREATE OR ALTER PROCEDURE SetForgottenPassword
    @Email NVARCHAR(50),
    @NewPassword NVARCHAR(50),
    @ResetToken NVARCHAR(50),
    @ResetResult NVARCHAR(100) OUTPUT
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @UserID INT;
    DECLARE @PasswordSalt NVARCHAR(50);
    DECLARE @PasswordHash VARBINARY(64);
    DECLARE @TokenExpiry DATETIME;
    DECLARE @StoredToken NVARCHAR(50);
    DECLARE @IsUsed BIT;

    
    SELECT 
        @UserID = pr.UserID, 
        @StoredToken = pr.ResetCode, 
        @TokenExpiry = pr.ExpiresAt,
        @IsUsed = pr.IsUsed
    FROM hhb.PasswordReset pr
    INNER JOIN hhb.Users u ON u.UserID = pr.UserID
    WHERE u.Email = @Email;

    
    IF @UserID IS NULL
    BEGIN 
        SET @ResetResult = 'Fel: Ingen användare med denna e-postadress';
        SELECT @ResetResult AS Message;
        RETURN; 
    END;

    
    IF @StoredToken IS NULL OR @ResetToken <> @StoredToken
    BEGIN
        SET @ResetResult = 'Fel: Återställningstoken är ogiltig';
        SELECT @ResetResult AS Message;
        RETURN;
    END;

    
    IF @IsUsed = 1
    BEGIN 
        SET @ResetResult = 'Fel: Återställningstoken är redan använd';
        SELECT @ResetResult AS Message;
        RETURN;
    END;

    
    IF @TokenExpiry < GETDATE()
    BEGIN 
        SET @ResetResult = 'Fel: Återställningstoken har gått ut';
        SELECT @ResetResult AS Message;
        RETURN;
    END;

    
    SET @PasswordSalt = CONVERT(NVARCHAR(50), NEWID());
    SET @PasswordHash = HASHBYTES('SHA2_512', @NewPassword + @PasswordSalt);

    
    UPDATE hhb.Users 
    SET PasswordHash = @PasswordHash,
        PasswordSalt = @PasswordSalt
    WHERE UserID = @UserID;

    
    UPDATE hhb.PasswordReset 
    SET IsUsed = 1
    WHERE UserID = @UserID;

    
    SET @ResetResult = 'Lösenordet har uppdaterats framgångsrikt';
    SELECT @ResetResult AS Message;
END;

GO
DECLARE @NewPassword NVARCHAR(50) = NULL; -- Skriv in nytt lösenord
DECLARE @ResetToken NVARCHAR(50) = NULL; -- Skriv in resettoken 
DECLARE @ResetResult NVARCHAR(100);


IF @NewPassword IS NOT NULL AND @ResetToken IS NOT NULL
BEGIN
    EXEC SetForgottenPassword 
        @Email = 'daniilo@gmail.com',
        @NewPassword = @NewPassword,
        @ResetToken = @ResetToken,
        @ResetResult = @ResetResult OUTPUT;

    SELECT @ResetResult AS Result;
END
ELSE
BEGIN
    SELECT 'Skriv in nytt lösenord och resettoken för att uptatera lösenordet' AS StorProcedureSetForgottenPasswordMessage;
END;

GO


CREATE OR ALTER VIEW UserLoginReport AS
WITH LatestLogin AS (
     SELECT 
	 u.UserID,
	 u.FirstName,
	 u.LastName,
	 MAX(CASE WHEN la.Success = 1 THEN la.TimeAttempt ELSE NULL END) AS LastSuccessfullLogin,
	 MAX(CASE WHEN la.Success = 0 THEN la.TimeAttempt ELSE NULL END) AS LastFailedLogin
	 FROM hhb.Users u
	 LEFT JOIN hhb.LoginAttempts la ON u.UserID = la.UserID
	 GROUP BY u.UserID,u.FirstName,u.LastName
	 )
	 SELECT *
	 FROM LatestLogin

GO

	 SELECT *
     FROM UserLoginReport
GO

CREATE OR ALTER VIEW LoginAttemptsReport AS
SELECT 
  IpAdress,
  CAST(TimeAttempt AS DATE) AS AttemptDate,
  COUNT(*) OVER (PARTITION BY IpAdress ORDER BY CAST(TimeAttempt AS DATE)) AS TotalAttempts,
  SUM(CASE WHEN Success = 1 THEN 1 ELSE 0 END) OVER (PARTITION BY IpAdress ORDER BY  CAST(TimeAttempt AS DATE)) AS SuccesfulAtempts,
  SUM(CASE WHEN Success = 0 THEN 1 ELSE 0 END) OVER (PARTITION BY IpAdress ORDER BY  CAST(TimeAttempt AS DATE)) AS FailedAtempts,
  AVG(CASE WHEN Success = 1 THEN 1.0 ELSE 0 END) OVER (PARTITION BY IpAdress ORDER BY  CAST(TimeAttempt AS DATE)) AS AvgSuccesfulAtempts
FROM hhb.LoginAttempts

go

SELECT *
FROM LoginAttemptsReport


go



