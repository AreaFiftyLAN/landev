/*
 * Copyright (c) 2016  W.I.S.V. 'Christiaan Huygens'
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


package ch.wisv.areafiftylan;

import ch.wisv.areafiftylan.security.token.TeamInviteToken;
import ch.wisv.areafiftylan.security.token.repository.TeamInviteTokenRepository;
import ch.wisv.areafiftylan.teams.model.Team;
import ch.wisv.areafiftylan.teams.service.TeamRepository;
import ch.wisv.areafiftylan.users.model.User;
import io.restassured.http.ContentType;
import io.restassured.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static io.restassured.RestAssured.when;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.IsCollectionContaining.hasItem;


public class TeamRestIntegrationTest extends XAuthIntegrationTest {

    @Autowired
    protected TeamRepository teamRepository;

    @Autowired
    private TeamInviteTokenRepository teamInviteTokenRepository;

    private final String TEAM_ENDPOINT = "/teams/";

    private Map<String, String> getTeamDTO(User captain) {
        Map<String, String> team = new HashMap<>();
        team.put("captainUsername", captain.getUsername());
        team.put("teamName", "Team + " + captain.getId());
        return team;

    }

    //region Test Create Teams
    @Test
    public void testCreateTeamAsCaptain() {
        User captain = createUserWithTicket();
        Map<String, String> teamDTO = getTeamDTO(captain);

        //@formatter:off
        Integer teamId =
            given().
                header(getXAuthTokenHeaderForUser(captain)).
            when().
                body(teamDTO).
                contentType(ContentType.JSON).
                post(TEAM_ENDPOINT).
            then().
                statusCode(HttpStatus.SC_CREATED).
                header("Location", containsString("/teams/")).
                body("object.teamName", equalTo(teamDTO.get("teamName"))).
                body("object.captain.profile.displayName", equalTo(captain.getProfile().getDisplayName())).
                body("object.members", hasSize(1)).
            extract().response().path("object.id");
        //@formatter:on

        Team team = teamRepository.getOne(new Long(teamId));
        Assert.assertNotNull(team);
    }

    @Test
    public void testCreateTeamAsCaptainDifferentCase() {
        User captain = createUserWithTicket();
        Map<String, String> teamDTO = getTeamDTO(captain);
        teamDTO.put("captainUsername", captain.getUsername().toUpperCase());

        //@formatter:off
        Integer teamId =
            given().
                header(getXAuthTokenHeaderForUser(captain)).
            when().
                body(teamDTO).contentType(ContentType.JSON).
                post(TEAM_ENDPOINT).
            then().
                statusCode(HttpStatus.SC_CREATED).
                header("Location", containsString("/teams/")).
                body("object.teamName", equalTo(teamDTO.get("teamName"))).
                body("object.captain.profile.displayName", equalTo(captain.getProfile().getDisplayName())).
                body("object.members", hasSize(1)).
            extract().response().path("object.id");
        //@formatter:on

        Team team = teamRepository.getOne(new Long(teamId));
        Assert.assertNotNull(team);
    }

    @Test
    public void testCreateTeamMissingTicket() {
        User captain = createUser();

        Map<String, String> teamDTO = getTeamDTO(captain);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            body(teamDTO).contentType(ContentType.JSON).
            post(TEAM_ENDPOINT).
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testCreateTeamAsUserMissingCaptainParameter() {

        User captain = createUserWithTicket();
        Map<String, String> teamDTO = getTeamDTO(captain);
        teamDTO.remove("captainUsername");


        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            body(teamDTO).contentType(ContentType.JSON).
            post(TEAM_ENDPOINT).
        then().
            statusCode(HttpStatus.SC_BAD_REQUEST);
        //@formatter:on
    }

    @Test
    public void testCreateTeamWithDifferentCaptainUsername() {
        User user = createUserWithTicket();
        User captain = createUserWithTicket();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            body(getTeamDTO(user)).contentType(ContentType.JSON).
            post(TEAM_ENDPOINT).
        then().
            statusCode(HttpStatus.SC_BAD_REQUEST);
        //@formatter:on
    }

    @Test
    public void testCreateTeamAsAdminWithDifferentCaptain() {
        User admin = createUser(true);
        User captain = createUserWithTicket();

        Map<String, String> teamDTO = getTeamDTO(captain);
        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            body(teamDTO).contentType(ContentType.JSON).
            post(TEAM_ENDPOINT).
        then().
            statusCode(HttpStatus.SC_CREATED).
            header("Location", containsString("/teams/")).
            body("object.teamName", equalTo(teamDTO.get("teamName"))).
            body("object.captain.profile.displayName", equalTo(captain.getProfile().getDisplayName())).
            body("object.members", hasSize(1));
        //@formatter:on
    }

    @Test
    public void testCreateTeamAsUserDuplicateTeamName() {
        User captain = createUserWithTicket();
        User captain2 = createUserWithTicket();
        Map<String, String> teamDTO = getTeamDTO(captain);
        Map<String, String> teamDTO2 = getTeamDTO(captain2);
        teamDTO2.put("teamName", teamDTO.get("teamName"));

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            body(teamDTO).contentType(ContentType.JSON).
            post(TEAM_ENDPOINT).
        then().
            statusCode(HttpStatus.SC_CREATED).
            header("Location", containsString("/teams/")).
            body("object.teamName", equalTo(teamDTO.get("teamName"))).
            body("object.captain.profile.displayName", equalTo(captain.getProfile().getDisplayName())).
            body("object.members.profile.displayName", hasItem(captain.getProfile().getDisplayName()));

        given().
            header(getXAuthTokenHeaderForUser(captain2)).
        when().
            body(teamDTO2).contentType(ContentType.JSON).
            post(TEAM_ENDPOINT).
        then().
            statusCode(HttpStatus.SC_CONFLICT);
        //@formatter:on
    }

    @Test
    public void testCreateTeamAsUserDuplicateTeamNameDifferentCasing() {
        User captain = createUserWithTicket();
        Map<String, String> teamDTO = getTeamDTO(captain);
        User user = createUserWithTicket();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            body(teamDTO).contentType(ContentType.JSON).
            post(TEAM_ENDPOINT).
        then().
            statusCode(HttpStatus.SC_CREATED).
            header("Location", containsString("/teams/")).
            body("object.teamName", equalTo(teamDTO.get("teamName"))).
            body("object.captain.profile.displayName", equalTo(captain.getProfile().getDisplayName())).
            body("object.members.profile.displayName", hasItem(captain.getProfile().getDisplayName()));

        Map<String, String> teamDTO2 = getTeamDTO(user);
        teamDTO2.put("teamName", teamDTO.get("teamName").toUpperCase());

        given().
                header(getXAuthTokenHeaderForUser(user)).
                when().
                body(teamDTO).contentType(ContentType.JSON).
                post(TEAM_ENDPOINT).
                then().
                statusCode(HttpStatus.SC_CONFLICT);
        //@formatter:on
    }
    //endregion

    //region Test Get Team
    @Test
    public void getTeamAsAdmin() {
        User admin = createUser(true);
        User captain = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);
        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            get(TEAM_ENDPOINT + team.getId()).
        then().
            statusCode(HttpStatus.SC_OK);
        //formatter:on
    }

    @Test
    public void getTeamAsCaptain() {
        User captain = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);
        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            get(TEAM_ENDPOINT + team.getId()).
        then().
            statusCode(HttpStatus.SC_OK);
        //formatter:on
    }

    @Test
    public void getTeamAsMember() {
        User captain = createUserWithTicket();
        User member = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);
        team = addMemberToTeam(team, member);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(member)).
        when().
            get(TEAM_ENDPOINT + team.getId()).
        then().
            statusCode(HttpStatus.SC_OK);
        //formatter:on
    }

    @Test
    public void getTeamAsUser() {
        User captain = createUserWithTicket();
        User user = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            get(TEAM_ENDPOINT + team.getId()).
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //formatter:on
    }

    @Test
    public void getTeamCurrentUser() {
        User captain = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            get("/users/current/teams").
        then().
            statusCode(HttpStatus.SC_OK).
            body("[0].teamName", equalTo(team.getTeamName())).
            body("[0].captain.profile.displayName", equalTo(captain.getProfile().getDisplayName())).
            body("[0].members.profile.displayName", hasItem(captain.getProfile().getDisplayName()));
        //@formatter:on
    }
    //endregion

    //region Test Add/Invite Members
    @Test
    public void testInviteMemberAsAdmin() {
        User captain = createUserWithTicket();
        User admin = createUser(true);
        User member = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);
        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            body(member.getUsername()).
            post(TEAM_ENDPOINT + team.getId() + "/invites").
        then().
            statusCode(HttpStatus.SC_OK);
        //@formatter:on

        Collection<TeamInviteToken> tokens =
                teamInviteTokenRepository.findByUserUsernameIgnoreCase(member.getUsername());
        Assert.assertFalse(tokens.isEmpty());
    }

    @Test
    public void testAddMemberAsAdmin() {
        User captain = createUserWithTicket();
        User admin = createUser(true);
        User member = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);

        //@formatter:off
        Header header = getXAuthTokenHeaderForUser(admin);

        given().
            header(header).
        when().
            body(member.getUsername()).
            post(TEAM_ENDPOINT + team.getId()).
        then().
            statusCode(HttpStatus.SC_OK);

        given().
            header(header).
        when().
            get(TEAM_ENDPOINT + team.getId()).
        then().
            statusCode(HttpStatus.SC_OK).
            body("members.profile.displayName", hasItems(
                    captain.getProfile().getDisplayName(),
                    member.getProfile().getDisplayName())).
            body("size", equalTo(2));
        //@formatter:on
    }

    @Test
    public void testInviteMemberAsCaptain() {
        User captain = createUserWithTicket();
        User member = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);


        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            body(member.getUsername()).
            post(TEAM_ENDPOINT + team.getId() + "/invites").
        then().
            statusCode(HttpStatus.SC_OK);
        //@formatter:on

        Collection<TeamInviteToken> tokens =
                teamInviteTokenRepository.findByUserUsernameIgnoreCase(member.getUsername());
        Assert.assertFalse(tokens.isEmpty());
    }

    @Test
    public void testInviteMemberTwiceAsCaptain() {
        User captain = createUserWithTicket();
        User user = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);

        //@formatter:off
        Header header = getXAuthTokenHeaderForUser(captain);

        given().
            header(header).
        when().
            body(user.getUsername()).
            post(TEAM_ENDPOINT + team.getId() + "/invites").
        then().
            statusCode(HttpStatus.SC_OK);

        given().
            header(header).
        when().
            body(user.getUsername()).
            post(TEAM_ENDPOINT + team.getId() + "/invites").
        then().
            statusCode(HttpStatus.SC_CONFLICT);
        //@formatter:on

        Collection<TeamInviteToken> tokens = teamInviteTokenRepository.findByUserUsernameIgnoreCase(user.getUsername());
        Assert.assertEquals(1, tokens.size());
    }

    @Test
    public void testAddMemberAsMember() {
        User captain = createUser();
        Team team = createTeamWithCaptain(captain);
        User member = createUserWithTicket();
        User member2 = createUserWithTicket();
        team = addMemberToTeam(team, member);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(member)).
        when().
            body(member2.getUsername()).
            post(TEAM_ENDPOINT + team.getId()).
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testInviteMemberAsMember() {
        User captain = createUser();
        Team team = createTeamWithCaptain(captain);
        User member = createUserWithTicket();
        User member2 = createUserWithTicket();
        team = addMemberToTeam(team, member);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(member)).
        when().
            body(member2.getUsername()).
            post(TEAM_ENDPOINT + team.getId() + "/invites").
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testAddMemberAsUser() {
        User captain = createUser();
        Team team = createTeamWithCaptain(captain);
        User member = createUserWithTicket();
        User user = createUserWithTicket();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(member.getUsername()).
            post(TEAM_ENDPOINT + team.getId()).
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testInviteMemberAsUser() {
        User captain = createUser();
        Team team = createTeamWithCaptain(captain);
        User member = createUserWithTicket();
        User user = createUserWithTicket();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(member.getUsername()).
            post(TEAM_ENDPOINT + team.getId() + "/invites").
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testAddSelfToTeamAsCaptain() {
        User captain = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            body(captain.getUsername()).
            post(TEAM_ENDPOINT + team.getId()).
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testInviteSelfToTeamAsCaptain() {
        User captain = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            body(captain.getUsername()).
            post(TEAM_ENDPOINT + team.getId() + "/invites").
        then().
            statusCode(HttpStatus.SC_CONFLICT);
        //@formatter:on
    }

    @Test
    public void testInviteMemberAsCaptainDuplicate() {
        User captain = createUser();
        Team team = createTeamWithCaptain(captain);
        User member = createUserWithTicket();
        team = addMemberToTeam(team, member);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            body(member.getUsername()).
            post(TEAM_ENDPOINT + team.getId() + "/invites").
        then().
            statusCode(HttpStatus.SC_CONFLICT);
        //@formatter:on
    }

    @Test
    public void testInviteMemberWithoutTicket() {
        User captain = createUser();
        Team team = createTeamWithCaptain(captain);
        User member = createUser();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            body(member.getUsername()).
            post(TEAM_ENDPOINT + team.getId() + "/invites").
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testAddMemberAsAdminDuplicate() {
        User admin = createUser(true);
        User captain = createUserWithTicket();
        User member = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);
        team = addMemberToTeam(team, member);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            body(member.getUsername()).
            post(TEAM_ENDPOINT + team.getId()).
        then().
            statusCode(HttpStatus.SC_CONFLICT);
        //@formatter:on
    }
    //endregion

    //region Test Accept View Delete Invites

    @Test
    public void testViewCurrentUserInvites() {
        User captain = createUserWithTicket();
        User user = createUser();
        Team team = createTeamWithCaptain(captain);
        teamInviteTokenRepository.save(new TeamInviteToken(user, team));

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            get("/users/current/teams/invites").
        then().
            statusCode(HttpStatus.SC_OK).
            body("teamName", hasItem(equalTo(team.getTeamName()))).
            body("username", hasItem(equalTo(user.getUsername()))).
            body("$", hasSize(1));
        //@formatter:on
    }

    @Test
    public void testViewTeamInvitesAsCaptain() {
        User captain = createUserWithTicket();
        User user = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);
        teamInviteTokenRepository.save(new TeamInviteToken(user, team));

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            get(TEAM_ENDPOINT + team.getId() + "/invites").
        then().
            statusCode(HttpStatus.SC_OK).
            body("teamName", hasItem(equalTo(team.getTeamName()))).
            body("username", hasItem(equalTo(user.getUsername()))).
            body("$", hasSize(1));
        //@formatter:on
    }

    @Test
    public void testViewTeamInvitesAsMember() {
        User captain = createUserWithTicket();
        User member = createUserWithTicket();
        User user = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);
        team = addMemberToTeam(team, member);
        teamInviteTokenRepository.save(new TeamInviteToken(user, team));

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(member)).
        when().
            get(TEAM_ENDPOINT + team.getId() + "/invites").
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testViewTeamInvitesAsAdmin() {
        User captain = createUserWithTicket();
        User admin = createUser(true);
        User user = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);
        teamInviteTokenRepository.save(new TeamInviteToken(user, team));

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            get(TEAM_ENDPOINT + team.getId() + "/invites").
        then().
            statusCode(HttpStatus.SC_OK).
            body("teamName", hasItem(equalTo(team.getTeamName()))).
            body("username", hasItem(equalTo(user.getUsername()))).
            body("$", hasSize(1));
        //@formatter:on
    }

    @Test
    public void testViewTeamInvitesAsAnon() {
        User captain = createUserWithTicket();
        User user = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);
        teamInviteTokenRepository.save(new TeamInviteToken(user, team));

        //@formatter:off
        when().
            get(TEAM_ENDPOINT + team.getId() + "/invites").
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testAcceptInviteAsUser() {
        User captain = createUserWithTicket();
        User user = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);

        TeamInviteToken token = teamInviteTokenRepository.save(new TeamInviteToken(user, team));

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(token.getToken()).
            post(TEAM_ENDPOINT + "invites").
        then().
            statusCode(HttpStatus.SC_OK);
        //@formatter:on

        Collection<Team> allByMembersUsername = teamRepository.findAllByMembersUsernameIgnoreCase(user.getUsername());
        Assert.assertFalse(allByMembersUsername.isEmpty());
    }

    @Test
    public void testDeclineInviteAsUser() {
        User captain = createUserWithTicket();
        User user = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);

        TeamInviteToken token = teamInviteTokenRepository.save(new TeamInviteToken(user, team));

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(token.getToken()).
            post(TEAM_ENDPOINT + "invites").
        then().
            statusCode(HttpStatus.SC_OK);
        //@formatter:on


        Collection<TeamInviteToken> tokens = teamInviteTokenRepository.findByUserUsernameIgnoreCase(user.getUsername());
        tokens.removeIf(t -> !t.isValid());

        Assert.assertTrue(tokens.isEmpty());
    }

    //endregion

    //region Test Remove Members
    @Test
    public void testRemoveMemberAsCaptain() {
        User captain = createUserWithTicket();
        User member = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);
        team = addMemberToTeam(team, member);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            body(member.getUsername()).
            delete(TEAM_ENDPOINT + team.getId() + "/members").
        then().
            statusCode(HttpStatus.SC_OK);
        //@formatter:on
    }

    @Test
    public void testRemoveCaptainAsCaptain() {
        User captain = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(captain)).
        when().
            body(captain.getUsername()).
            delete(TEAM_ENDPOINT + team.getId() + "/members").
        then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testRemoveMemberAsdmin() {
        User admin = createUser(true);
        User captain = createUserWithTicket();
        User member = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);
        team = addMemberToTeam(team, member);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            body(member.getUsername()).
            delete(TEAM_ENDPOINT + team.getId() + "/members").
        then().
            statusCode(HttpStatus.SC_OK);
        //@formatter:on
    }

    @Test
    public void testRemoveSelf() {
        User captain = createUserWithTicket();
        User member = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);
        team = addMemberToTeam(team, member);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(member)).
        when().
            body(member.getUsername()).
            delete(TEAM_ENDPOINT + team.getId() + "/members").
        then().
            statusCode(HttpStatus.SC_OK);
        //@formatter:on
    }

    @Test
    public void testRemoveMemberAsUser() {
        User captain = createUserWithTicket();
        User member = createUserWithTicket();
        User user = createUserWithTicket();
        Team team = createTeamWithCaptain(captain);
        team = addMemberToTeam(team, member);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(member.getUsername()).
            delete(TEAM_ENDPOINT + team.getId() + "/members").
        then().
                statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }
    //endregion
}
