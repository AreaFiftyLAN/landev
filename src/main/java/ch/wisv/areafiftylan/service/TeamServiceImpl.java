package ch.wisv.areafiftylan.service;

import ch.wisv.areafiftylan.dto.TeamDTO;
import ch.wisv.areafiftylan.exception.TeamNotFoundException;
import ch.wisv.areafiftylan.exception.TokenNotFoundException;
import ch.wisv.areafiftylan.exception.UserNotFoundException;
import ch.wisv.areafiftylan.model.Team;
import ch.wisv.areafiftylan.model.User;
import ch.wisv.areafiftylan.security.TeamInviteToken;
import ch.wisv.areafiftylan.service.repository.TeamRepository;
import ch.wisv.areafiftylan.service.repository.token.TeamInviteTokenRepository;
import com.google.common.base.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

@Service
public class TeamServiceImpl implements TeamService {
    private final TeamRepository teamRepository;
    private final UserService userService;
    private final MailService mailService;
    private final TeamInviteTokenRepository teamInviteTokenRepository;

    @Autowired
    public TeamServiceImpl(TeamRepository teamRepository, UserService userService, MailService mailService,
                           TeamInviteTokenRepository teamInviteTokenRepository) {
        this.teamRepository = teamRepository;
        this.teamInviteTokenRepository = teamInviteTokenRepository;
        this.userService = userService;
        this.mailService = mailService;
    }

    @Override
    public Team create(String username, String teamname) {
        User captain =
                userService.getUserByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username));
        Team team = new Team(teamname, captain);

        return teamRepository.saveAndFlush(team);
    }

    @Override
    public Team save(Team team) {
        return teamRepository.saveAndFlush(team);
    }

    @Override
    public Team getTeamById(Long teamId) {
        return teamRepository.getOne(teamId);
    }

    @Override
    public Optional<Team> getTeamByTeamname(String teamname) {
        return teamRepository.findByTeamName(teamname);
    }

    @Override
    public Collection<Team> getTeamByCaptainId(Long userId) {
        return teamRepository.findByCaptainId(userId);
    }

    @Override
    public Collection<Team> getAllTeams() {
        return teamRepository.findAll();
    }

    @Override
    public Collection<Team> getTeamsByUsername(String username) {
        return teamRepository.findAllByMembersUsername(username);
    }

    @Override
    public Team update(Long teamId, TeamDTO input) {
        Team current = this.getTeamById(teamId);

        // If the Teamname is set, change the Teamname
        if (!Strings.isNullOrEmpty(input.getTeamName())) {
            current.setTeamName(input.getTeamName());
        }

        // If the Captain username is set, change the Captain
        if (!Strings.isNullOrEmpty(input.getCaptainUsername())) {
            User captain = userService.getUserByUsername(input.getCaptainUsername()).get();
            current.setCaptain(captain);
        }

        return teamRepository.saveAndFlush(current);
    }

    @Override
    public Team delete(Long teamId) {
        Team team = teamRepository.getOne(teamId);
        teamRepository.delete(teamId);
        return team;
    }

    @Override
    public void inviteMember(Long teamId, String username) {
        User user = userService.getUserByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username));
        Team team = getTeamById(teamId).orElseThrow(() -> new TeamNotFoundException(teamId));
        String token = UUID.randomUUID().toString();

        TeamInviteToken inviteToken = new TeamInviteToken(token, user, team);

        teamInviteTokenRepository.save(inviteToken);

        try {
            mailService.sendTeamInviteMail(user, team.getTeamName());
        } catch (MessagingException e) {
            // TODO: Fix mailservice exception handling
            e.printStackTrace();
        }
    }

    @Override
    public void addMemberByInvite(String token) {
        TeamInviteToken teamInviteToken =
                teamInviteTokenRepository.findByToken(token).orElseThrow(() -> new TokenNotFoundException(token));
        addMember(teamInviteToken.getTeam().getId(), teamInviteToken.getUser().getUsername());

    }

    @Override
    public void addMember(Long teamId, String username) {
        Team team = teamRepository.getOne(teamId);
        User user = userService.getUserByUsername(username).orElseThrow(() -> new UserNotFoundException(username));
        if (team.addMember(user)) {
            teamRepository.saveAndFlush(team);
        } else {
            throw new IllegalArgumentException("Could not add User to Team");
        }
    }

    @Override
    public boolean removeMember(Long teamId, String username) {
        Team team = teamRepository.getOne(teamId);
        User user = userService.getUserByUsername(username).orElseThrow(() -> new UserNotFoundException(username));
        if (team.getCaptain().equals(user)) {
            return false;
        }
        boolean success = team.removeMember(user);
        if (success) {
            teamRepository.saveAndFlush(team);
        }
        return success;

    }
}
