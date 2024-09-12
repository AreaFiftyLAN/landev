/*
 * Copyright (c) 2018  W.I.S.V. 'Christiaan Huygens'
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package ch.wisv.areafiftylan.integration;

import ch.wisv.areafiftylan.products.model.Ticket;
import ch.wisv.areafiftylan.security.token.repository.VerificationTokenRepository;
import ch.wisv.areafiftylan.users.model.Role;
import ch.wisv.areafiftylan.users.model.RoleDTO;
import ch.wisv.areafiftylan.users.model.User;
import io.restassured.http.ContentType;
import io.restassured.http.Header;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static io.restassured.RestAssured.when;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

public class UserRestIntegrationTest extends XAuthIntegrationTest {

    @Autowired
    private VerificationTokenRepository verificationTokenRepository;

    static Map<String, String> getProfileDTO() {
        Map<String, String> profileDTO = new HashMap<>();
        profileDTO.put("birthday", "2000-01-02");
        profileDTO.put("gender", "MALE");
        profileDTO.put("address", "Testaddress");
        profileDTO.put("zipcode", "Testzipcode");
        profileDTO.put("city", "Testcity");
        profileDTO.put("phoneNumber", "TestphoneNumber");
        profileDTO.put("notes", "Testnotes");
        profileDTO.put("firstName", "TestfirstName");
        profileDTO.put("lastName", "TestlastName");
        profileDTO.put("displayName", "TestdisplayName");
        return profileDTO;
    }

    @Test
    public void testGetAllUsersAsAnonymous() {
        //@formatter:off
        when().
            get("/users").
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testGetAllUsersAsUser() {
        User user = createUser();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            get("/users").
        then().
            statusCode(HttpStatus.SC_FORBIDDEN).
            body("message", equalTo("Access denied"));
        //@formatter:on
    }

    @Test
    public void testGetAllUsersAsAdmin() {
        User user = createUser();
        User admin = createAdmin();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            get("/users").
        then().
            statusCode(HttpStatus.SC_OK).
            body("email", hasItems(user.getEmail(), admin.getEmail())).
            body("profile.displayName",
            hasItems(user.getProfile().getDisplayName(), admin.getProfile().getDisplayName()));
        //@formatter:on
    }

    @Test
    public void testGetCurrentUserAsAnonymous() {
        //@formatter:off
        when().
            get("/users/current").
        then().
            statusCode(HttpStatus.SC_OK).
            body("object", nullValue()).
            body("message", containsString("Not logged in"));

        //@formatter:on
    }

    @Test
    public void testGetCurrentUserAsUser() {
        User user = createUser();
        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            get("/users/current").
        then().
            statusCode(HttpStatus.SC_OK).
            body("email", equalTo(user.getEmail())).
            body("authorities", hasItem("ROLE_USER")).
            body("authorities", not(hasItem("ROLE_ADMIN")));
        //@formatter:on
    }

    @Test
    public void testGetCurrentUserHasNoPasswordHash() {
        User user = createUser();
        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            get("/users/current").
        then().
            body("passwordHash", isEmptyOrNullString());
        //@formatter:on
    }

    @Test
    public void testGetCurrentUserAsAdmin() {
        User admin = createAdmin();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            get("/users/current").
        then().statusCode(HttpStatus.SC_OK).
            body("email", equalTo(admin.getEmail())).
            body("authorities", hasItem("ROLE_ADMIN"));
        //@formatter:on
    }

    @Test
    public void testGetOtherUserAsAnonymous() {
        //@formatter:off
        when().
            get("/users/1").
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testGetOtherUserAsUser() {
        User user = createUser();
        long id = user.getId();
        id++;

        //@formatter:off
        given().
                header(getXAuthTokenHeaderForUser(user)).
        when().get("/users/" + id).
            then().statusCode(HttpStatus.SC_FORBIDDEN).body("message", equalTo("Access denied"));
        //@formatter:on
    }

    @Test
    public void testGetOtherUserAsAdmin() {
        User user = createUser();
        long userId = user.getId();
        User admin = createAdmin();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            get("/users/" + userId).
        then().statusCode(HttpStatus.SC_OK).
            body("email", equalTo(user.getEmail()));
        //@formatter:on
    }

    @Test
    public void testGetOwnUserId() {
        User user = createUser();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            get("/users/" + user.getId()).
        then().statusCode(HttpStatus.SC_OK).
            body("email", equalTo(user.getEmail()));
        //@formatter:on
    }


    // USER POST
    @Test
    public void testCreateUser() {
        Map<String, String> userDTO = new HashMap<>();
        userDTO.put("email", "test@mail.com");
        userDTO.put("password", cleartextPassword);

        //@formatter:off
        given().
        when().
            body(userDTO).contentType(ContentType.JSON).
            post("/users").
        then().
            statusCode(HttpStatus.SC_CREATED).
            body("message", containsString("User successfully created at")).
            body("object.email", is(userDTO.get("email")));
        //@formatter:on
    }

    @Test
    public void testCreateUserIsDisabled() {
        Map<String, String> userDTO = new HashMap<>();
        userDTO.put("email", "disabled@mail.com");
        userDTO.put("password", cleartextPassword);

        //@formatter:off
        given().
        when().
            body(userDTO).contentType(ContentType.JSON).
            post("/users").
        then().
            statusCode(HttpStatus.SC_CREATED).
            body("message", containsString("User successfully created at")).
            body("object.email", is(userDTO.get("email")));

        given().
            body(userDTO).
        when().
            post("/login").
        then().
            statusCode(HttpStatus.SC_UNAUTHORIZED).
            body("error", containsString("Unauthorized"));
        //@formatter:on

    }

    @Test
    public void createUserMissingEmailField() {
        Map<String, String> userDTO = new HashMap<>();
        userDTO.put("password", "password");

        //@formatter:off
        given().
        when().
            body(userDTO).contentType(ContentType.JSON).
            post("/users").
        then().
            statusCode(HttpStatus.SC_BAD_REQUEST);
        //@formatter:on
    }

    @Test
    public void createUserEmptyEmailField() {
        Map<String, String> userDTO = new HashMap<>();
        userDTO.put("email", "");
        userDTO.put("password", "password");

        //@formatter:off
        given().
        when().
            body(userDTO).contentType(ContentType.JSON).
            post("/users").
        then().
            statusCode(HttpStatus.SC_BAD_REQUEST);
        //@formatter:on
    }

    @Test
    public void createUserMissingPasswordField() {
        Map<String, String> userDTO = new HashMap<>();
        userDTO.put("email", "testUser");

        //@formatter:off
        given().
        when().
            body(userDTO).contentType(ContentType.JSON).
            post("/users").
        then().
            statusCode(HttpStatus.SC_BAD_REQUEST);
        //@formatter:on
    }

    @Test
    public void createUserEmptyPasswordField() {
        Map<String, String> userDTO = new HashMap<>();
        userDTO.put("email", "testEmail");
        userDTO.put("password", "");

        //@formatter:off
        given().
        when().
            body(userDTO).contentType(ContentType.JSON).
            post("/users").
        then().
            statusCode(HttpStatus.SC_BAD_REQUEST);
        //@formatter:on
    }

    @Test
    public void createUserTakenEmail() {
        User user = createUser();
        Map<String, String> userDTO = new HashMap<>();
        userDTO.put("email", user.getEmail());
        userDTO.put("password", cleartextPassword);

        //@formatter:off
        given().
        when().
            body(userDTO).contentType(ContentType.JSON).
            post("/users").
        then().
            statusCode(HttpStatus.SC_CONFLICT);
        //@formatter:on
    }

    @Test
    public void createUserTakenEmailDifferentCase() {
        User user = createUser();
        Map<String, String> userDTO = new HashMap<>();
        userDTO.put("email", user.getEmail().toUpperCase());
        userDTO.put("password", cleartextPassword);

        //@formatter:off
        given().
        when().
            body(userDTO).contentType(ContentType.JSON).
            post("/users").
        then().
            statusCode(HttpStatus.SC_CONFLICT);
        //@formatter:on
    }

    @Test
    public void createProfileAsCurrentUser() {
        User user = createUser();
        user.resetProfile();
        user = userRepository.save(user);

        Map<String, String> profileDTO = getProfileDTO();
        profileDTO.put("displayName", "TestdisplayName" + user.getId());

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(profileDTO).
            contentType(ContentType.JSON).
            post("/users/current/profile").
        then().
            statusCode(HttpStatus.SC_OK).
            body("object.birthday", equalTo(profileDTO.get("birthday"))).
            body("object.gender", equalTo("MALE")).
            body("object.address", equalTo("Testaddress")).
            body("object.zipcode", equalTo("Testzipcode")).
            body("object.city", equalTo("Testcity")).
            body("object.phoneNumber", equalTo("TestphoneNumber")).
            body("object.notes", equalTo("Testnotes")).
            body("object.firstName", equalTo("TestfirstName")).
            body("object.lastName", equalTo("TestlastName")).
            body("object.displayName", equalTo("TestdisplayName" + user.getId()));
        //@formatter:on
    }

    @Test
    public void createProfileAsUser() {
        User user = createUser();
        user.resetProfile();
        user = userRepository.save(user);

        Map<String, String> profileDTO = getProfileDTO();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(profileDTO).
            contentType(ContentType.JSON).
            post("/users/" + user.getId() + "/profile").
        then().
            statusCode(HttpStatus.SC_OK).
            body("object.birthday", equalTo("2000-01-02")).
            body("object.gender", is("MALE")).
            body("object.address", equalTo("Testaddress")).
            body("object.zipcode", equalTo("Testzipcode")).
            body("object.city", equalTo("Testcity")).
            body("object.phoneNumber", equalTo("TestphoneNumber")).
            body("object.notes", equalTo("Testnotes")).
            body("object.firstName", equalTo("TestfirstName")).
            body("object.lastName", equalTo("TestlastName")).
            body("object.displayName", equalTo("TestdisplayName"));
        //@formatter:on
    }

    @Test
    public void createProfileAsAdmin() {
        User user = createUser();
        user.resetProfile();
        user = userRepository.save(user);

        User admin = createAdmin();

        Map<String, String> profileDTO = getProfileDTO();
        profileDTO.put("displayName", "TestdisplayName" + user.getId());


        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            body(profileDTO).
            contentType(ContentType.JSON).
            post("/users/" + user.getId() + "/profile").
        then().
            statusCode(HttpStatus.SC_OK).
            body("object.birthday", equalTo("2000-01-02")).
            body("object.gender", is("MALE")).
            body("object.address", equalTo("Testaddress")).
            body("object.zipcode", equalTo("Testzipcode")).
            body("object.city", equalTo("Testcity")).
            body("object.phoneNumber", equalTo("TestphoneNumber")).
            body("object.notes", equalTo("Testnotes")).
            body("object.firstName", equalTo("TestfirstName")).
            body("object.lastName", equalTo("TestlastName")).
            body("object.displayName", equalTo("TestdisplayName" + user.getId()));
        //@formatter:on
    }

    @Test
    public void createProfileAsOtherUser() {
        User user = createUser();
        user.resetProfile();
        user = userRepository.save(user);

        User user2 = createUser();

        Map<String, String> profileDTO = getProfileDTO();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user2)).
        when().
            body(profileDTO).
            contentType(ContentType.JSON).
            post("/users/" + user.getId() + "/profile").
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void createProfileMissingField() {
        User user = createUser();
        user.resetProfile();
        user = userRepository.save(user);

        Map<String, String> profileDTO = getProfileDTO();
        profileDTO.remove("firstName");

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(profileDTO).
            contentType(ContentType.JSON).
            post("/users/current/profile").
        then().
            statusCode(HttpStatus.SC_BAD_REQUEST);
        //@formatter:on
    }

    @Test
    public void createProfileInvalidField() {
        User user = createUser();
        user.resetProfile();
        user = userRepository.save(user);

        Map<String, String> profileDTO = getProfileDTO();
        profileDTO.put("birthday", "unknown");

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(profileDTO).
            contentType(ContentType.JSON).
            post("/users/current/profile").
        then().
            statusCode(HttpStatus.SC_BAD_REQUEST);
        //@formatter:on
    }

    @Test
    public void createProfileEmptyField() {
        User user = createUser();
        user.resetProfile();
        user = userRepository.save(user);

        Map<String, String> profileDTO = getProfileDTO();
        profileDTO.put("displayName", "");

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(profileDTO).
            contentType(ContentType.JSON).
            post("/users/current/profile").
        then().
            statusCode(HttpStatus.SC_BAD_REQUEST);
        //@formatter:on
    }

    @Test
    public void createProfileDuplicateDisplayName() {
        User user = createUser();
        user.resetProfile();
        user = userRepository.save(user);

        User user2 = createUser();

        Map<String, String> profileDTO = getProfileDTO();
        profileDTO.put("displayName", user2.getProfile().getDisplayName().toUpperCase());

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(profileDTO).
            contentType(ContentType.JSON).
            post("/users/current/profile").
        then().
            statusCode(HttpStatus.SC_CONFLICT).
            body("message", equalTo("DisplayName already in use"));
        //@formatter:on
    }

    @Test
    public void deleteUserAsAdmin() {
        User user = createUser();
        User admin = createAdmin();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            delete("/users/" + user.getId()).
        then().
            statusCode(HttpStatus.SC_OK).
            body("message", equalTo("User disabled"));
        //@formatter:on

        User disabledUser = userRepository.findOneByEmailIgnoreCase(user.getEmail()).orElse(user);
        assertFalse(disabledUser.isAccountNonLocked());
    }

    @Test
    public void deleteUserAsUser() {
        User user = createUser();
        User user2 = createUser();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            delete("/users/" + user2.getId()).
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on

    }

    @Test
    public void deleteUserAsAnon() {
        User user = createUser();

        //@formatter:off
        when().
            delete("/users/" + user.getId()).
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testAlcoholCheckAsUser() {
        User user = createUser();

        //@formatter:off
        when().
            get("/users/" + user.getId() + "/alcoholcheck").
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testAlcoholCheckAsAdminUnderage() {
        User admin = createAdmin();
        User user = createUser(17, Role.ROLE_USER);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            get("/users/" + user.getId() + "/alcoholcheck").
        then().
            statusCode(HttpStatus.SC_OK).
            body("object", equalTo(false));
        //@formatter:on
    }

    @Test
    public void testAlcoholCheckAsAdminOverage() {
        User admin = createAdmin();
        User user = createUser(19, Role.ROLE_USER);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            get("/users/" + user.getId() + "/alcoholcheck").
        then().
            statusCode(HttpStatus.SC_OK).
            body("object", equalTo(true));
        //@formatter:on
    }

    @Test
    public void testChangePassword() {
        //TODO: Move to new AuthenticationTest
        User user = createUser();

        String newPassword = "newPassword";
        Map<String, String> passwordDTO = new HashMap<>();
        passwordDTO.put("oldPassword", cleartextPassword);
        passwordDTO.put("newPassword", newPassword);

        //@formatter:off
        Header xAuthTokenHeader = getXAuthTokenHeaderForUser(user);

        given().
            header(xAuthTokenHeader).
        when().
            body(passwordDTO).
            contentType(ContentType.JSON).
            post("/users/current/password").
        then().
            statusCode(HttpStatus.SC_OK);
        //@formatter:on

        removeXAuthToken(xAuthTokenHeader);

        Map<String, String> userDTO = new HashMap<>();
        userDTO.put("email", user.getEmail());
        userDTO.put("password", newPassword);

        //@formatter:off
        given().
            body(userDTO).
        when().
            post("/login").
        then().
            statusCode(HttpStatus.SC_OK).
            header("X-Auth-Token", not(isEmptyOrNullString()));
        //@formatter:on
    }

    @Test
    public void testChangeShortPassword() {
        //TODO: Move to new AuthenticationTest
        User user = createUser();

        String newPassword = "short";
        Map<String, String> passwordDTO = new HashMap<>();
        passwordDTO.put("oldPassword", cleartextPassword);
        passwordDTO.put("newPassword", newPassword);

        //@formatter:off
        Header xAuthTokenHeader = getXAuthTokenHeaderForUser(user);

        given().
            header(xAuthTokenHeader).
        when().
            body(passwordDTO).
            contentType(ContentType.JSON).
            post("/users/current/password").
        then().
            statusCode(HttpStatus.SC_NOT_MODIFIED);
        //@formatter:on
    }

    @Test
    public void testChangePasswordEmptyPassword() {
        //TODO: Move to new AuthenticationTest
        User user = createUser();

        String newPassword = "";
        Map<String, String> passwordDTO = new HashMap<>();
        passwordDTO.put("oldPassword", cleartextPassword);
        passwordDTO.put("newPassword", newPassword);

        //@formatter:off
        Header xAuthTokenHeader = getXAuthTokenHeaderForUser(user);

        given().
            header(xAuthTokenHeader).
        when().
            body(passwordDTO).
            contentType(ContentType.JSON).
            post("/users/current/password").
        then().
            statusCode(HttpStatus.SC_BAD_REQUEST);
        //@formatter:on

        removeXAuthToken(xAuthTokenHeader);

        Map<String, String> userDTO = new HashMap<>();
        userDTO.put("email", user.getEmail());
        userDTO.put("password", cleartextPassword);

        //@formatter:off
        given().
            body(userDTO).
        when().
            post("/login").
        then().
            statusCode(HttpStatus.SC_OK).
            header("X-Auth-Token", not(isEmptyOrNullString()));
        //@formatter:on
    }

    @Test
    public void testChangePasswordWrongOldPassword() {
        //TODO: Move to new AuthenticationTest
        User user = createUser();

        Map<String, String> passwordDTO = new HashMap<>();
        passwordDTO.put("oldPassword", "wrongPassword");
        passwordDTO.put("newPassword", "newPassword");

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(passwordDTO).
            contentType(ContentType.JSON).
            post("/users/current/password").
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testChangePasswordMissingOldPassword() {
        //TODO: Move to new AuthenticationTest

        User user = createUser();
        Map<String, String> passwordDTO = new HashMap<>();
        passwordDTO.put("newPassword", "newPassword");

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(passwordDTO).
            contentType(ContentType.JSON).
            post("/users/current/password").
        then().
            statusCode(HttpStatus.SC_BAD_REQUEST);
        //@formatter:on
    }

    @Test
    public void testChangePasswordShortNewPassword() {
        User user = createUser();
        Map<String, String> passwordDTO = new HashMap<>();
        passwordDTO.put("newPassword", "new");

        //@formatter:off
        given().
                header(getXAuthTokenHeaderForUser(user)).
                when().
                body(passwordDTO).
                contentType(ContentType.JSON).
                post("/users/current/password").
                then().
                statusCode(HttpStatus.SC_BAD_REQUEST);
        //@formatter:on
    }

    //TODO: Move to SchedulerTest
/*    @Test
    public void testExpiredUsersNoneExpired() {
        User tempUser = makeAndGetTempUser("");

        taskScheduler.CleanUpUsers();

        assertTrue(verificationTokenRepository.findByUser(tempUser).isPresent());
    }

    @Test
    public void testExpiredUsersSingleExpired() {
        User tempUser = makeAndGetTempUser("");

        VerificationToken token = verificationTokenRepository.findByUser(tempUser).get();
        token.setExpiryDate(LocalDateTime.now().minusDays(1));
        verificationTokenRepository.save(token);

        int expiredCount = verificationTokenRepository.findAllByExpiryDateBefore(LocalDateTime.now()).size();
        Assert.assertEquals(1, expiredCount);

        taskScheduler.CleanUpUsers();

        Assert.assertFalse(verificationTokenRepository.findByUser(tempUser).isPresent());
    }

    @Test
    public void testExpiredUsersMultipleExpired() {
        User tempUser1 = makeAndGetTempUser("1");
        User tempUser2 = makeAndGetTempUser("2");

        VerificationToken token1 = verificationTokenRepository.findByUser(tempUser1).get();
        VerificationToken token2 = verificationTokenRepository.findByUser(tempUser2).get();
        token1.setExpiryDate(LocalDateTime.now().minusDays(1));
        token2.setExpiryDate(LocalDateTime.now().minusDays(1));
        verificationTokenRepository.save(token1);
        verificationTokenRepository.save(token2);

        int expiredCount = verificationTokenRepository.findAllByExpiryDateBefore(LocalDateTime.now()).size();
        Assert.assertEquals(2, expiredCount);

        taskScheduler.CleanUpUsers();

        Assert.assertFalse(verificationTokenRepository.findByUser(tempUser1).isPresent());
        Assert.assertFalse(verificationTokenRepository.findByUser(tempUser2).isPresent());
    }*/

    @Test
    public void testWrongCaseLogin() {
        //TODO: Move to AuthenticationTest
        User user = createUser();
        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user.getEmail().toUpperCase())).
        when().
            get("/users/current").
        then().statusCode(HttpStatus.SC_OK).
            body("email", equalTo(user.getEmail())).
            body("authorities", hasItem("ROLE_USER"));
        //@formatter:on
    }

    @Test
    public void testAddRole() {
        User admin = createAdmin();
        User user = createUser();
        RoleDTO roleDTO = new RoleDTO();
        roleDTO.setRole(Role.ROLE_ADMIN);
        //@formatter:off
        given().
                header(getXAuthTokenHeaderForUser(admin.getEmail())).
        when().
                body(roleDTO).
                contentType(ContentType.JSON).
                post("/users/" + user.getId() + "/role").
        then().statusCode(HttpStatus.SC_OK).
                body("email", equalTo(user.getEmail())).
                body("authorities", hasItem("ROLE_ADMIN"));
        //@formatter:on
    }

    @Test
    public void testDeleteRole() {
        User admin = createAdmin();
        User user = createCommitteeMember();
        RoleDTO roleDTO = new RoleDTO();
        roleDTO.setRole(Role.ROLE_COMMITTEE);
        //@formatter:off
        given().
                header(getXAuthTokenHeaderForUser(admin.getEmail())).
        when().
                body(roleDTO).
                contentType(ContentType.JSON).
                post("/users/" + user.getId() + "/role/delete").
        then().statusCode(HttpStatus.SC_OK).
                body("email", equalTo(user.getEmail())).
                body("authorities", not(hasItem("ROLE_COMMITTEE")));
        //@formatter:on
    }

    @Test
    public void testDeleteUserRole() {
        User admin = createAdmin();
        User user = createUser();
        RoleDTO roleDTO = new RoleDTO();
        roleDTO.setRole(Role.ROLE_USER);
        //@formatter:off
        given().
                header(getXAuthTokenHeaderForUser(admin.getEmail())).
        when().
                body(roleDTO).
                contentType(ContentType.JSON).
                post("/users/" + user.getId() + "/role/delete").
        then().statusCode(HttpStatus.SC_BAD_REQUEST);
        //@formatter:on
    }

    @Test
    public void testDeleteNullRole() {
        User admin = createAdmin();
        User user = createUser();
        RoleDTO roleDTO = new RoleDTO();
        //@formatter:off
        given().
                header(getXAuthTokenHeaderForUser(admin.getEmail())).
        when().
                body(roleDTO).
                contentType(ContentType.JSON).
                post("/users/" + user.getId() + "/role/delete").
        then().statusCode(HttpStatus.SC_BAD_REQUEST);
        //@formatter:on
    }

    @Test
    public void createProfileAsCurrentUserAndChangeDate() {
        User user = createUser();
        Ticket ticket = createTicketForUser(user);
        createRFIDLink("", ticket);
        user.resetProfile();
        user.getProfile().setBirthday(LocalDate.now());
        user = userRepository.save(user);

        Map<String, String> profileDTO = getProfileDTO();
        profileDTO.put("displayName", "TestdisplayName" + user.getId());

        //@formatter:off
        given().
                header(getXAuthTokenHeaderForUser(user)).
                when().
                body(profileDTO).
                contentType(ContentType.JSON).
                post("/users/current/profile").
                then().
                statusCode(HttpStatus.SC_BAD_REQUEST).
                body("object.birthday", not(equalTo("2000-01-02"))).
                body("object.gender", equalTo(null)).
                body("object.address", equalTo(null)).
                body("object.zipcode", equalTo(null)).
                body("object.city", equalTo(null)).
                body("object.phoneNumber", equalTo(null)).
                body("object.notes", equalTo(null)).
                body("object.firstName", equalTo(null)).
                body("object.lastName", equalTo(null)).
                body("object.displayName", equalTo(null));
        //@formatter:on
    }

    @Test
    public void createProfileAsCurrentUserAndChangeProfileWithoutDate() {
        User user = createUser();
        Ticket ticket = createTicketForUser(user);
        createRFIDLink("", ticket);
        user = userRepository.save(user);

        Map<String, String> profileDTO = getProfileDTO();
        profileDTO.put("displayName", "TestdisplayName" + user.getId());
        profileDTO.put("birthday", user.getProfile().getBirthday().toString());

        //@formatter:off
        given().
                header(getXAuthTokenHeaderForUser(user)).
                when().
                body(profileDTO).
                contentType(ContentType.JSON).
                post("/users/current/profile").
                then().
                statusCode(HttpStatus.SC_OK).
                body("object.birthday", equalTo(user.getProfile().getBirthday().toString())).
                body("object.gender", equalTo("MALE")).
                body("object.address", equalTo("Testaddress")).
                body("object.zipcode", equalTo("Testzipcode")).
                body("object.city", equalTo("Testcity")).
                body("object.phoneNumber", equalTo("TestphoneNumber")).
                body("object.notes", equalTo("Testnotes")).
                body("object.firstName", equalTo("TestfirstName")).
                body("object.lastName", equalTo("TestlastName")).
                body("object.displayName", equalTo(profileDTO.get("displayName")));
        //@formatter:on
    }
}
