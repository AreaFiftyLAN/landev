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

package ch.wisv.areafiftylan.users.controller;


import ch.wisv.areafiftylan.products.model.Ticket;
import ch.wisv.areafiftylan.products.model.order.Order;
import ch.wisv.areafiftylan.products.service.OrderService;
import ch.wisv.areafiftylan.products.service.TicketService;
import ch.wisv.areafiftylan.seats.model.Seat;
import ch.wisv.areafiftylan.seats.service.SeatService;
import ch.wisv.areafiftylan.security.authentication.PasswordChangeDTO;
import ch.wisv.areafiftylan.teams.model.Team;
import ch.wisv.areafiftylan.teams.model.TeamInviteResponse;
import ch.wisv.areafiftylan.teams.service.TeamService;
import ch.wisv.areafiftylan.users.model.User;
import ch.wisv.areafiftylan.users.service.UserService;
import ch.wisv.areafiftylan.utils.view.View;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.List;

import static ch.wisv.areafiftylan.utils.ResponseEntityBuilder.createResponseEntity;

@RestController
@RequestMapping("/users/current")
@PreAuthorize("isAuthenticated()")
public class CurrentUserRestController {

    private final UserService userService;
    private final SeatService seatService;
    private final TeamService teamService;
    private final OrderService orderService;
    private final TicketService ticketService;

    @Autowired
    CurrentUserRestController(UserService userService, OrderService orderService, TicketService ticketService,
                              TeamService teamService, SeatService seatService) {
        this.userService = userService;
        this.seatService = seatService;
        this.orderService = orderService;
        this.ticketService = ticketService;
        this.teamService = teamService;
    }

    /**
     * The GET /users/current/ mapping is located in the UserRestController as all methods in this authentication
     * require
     * Authentication
     */

    /**
     * This mapping allows the user to change their password while logged in. This is different from the password reset
     * functionality which works with tokens. Users have to provide both their old and new password, and have to be
     * fully authenticated, meaning that they can't be coming from a "Remember me" session.
     *
     * @param user the current user
     * @param passwordChangeDTO DTO containing oldPassword and newPassword
     *
     * @return Statusmessage
     */
    @PostMapping("/password")
    public ResponseEntity<?> changeCurrentUserPassword(@AuthenticationPrincipal User user,
                                                       @RequestBody @Validated PasswordChangeDTO passwordChangeDTO) {
        try {
            userService.changePassword(user.getId(),
                    passwordChangeDTO.getOldPassword(), passwordChangeDTO.getNewPassword());
        } catch (Exception e) {
            if (e instanceof IllegalArgumentException) {
                return createResponseEntity(HttpStatus.NOT_MODIFIED, e.getMessage());

            } else if (e instanceof AccessDeniedException) {
                return createResponseEntity(HttpStatus.FORBIDDEN, e.getMessage());
            } else {
                return createResponseEntity(HttpStatus.INTERNAL_SERVER_ERROR, "Something went wrong, please try again!");
            }
        }

        return createResponseEntity(HttpStatus.OK, "Password successfully changed");
    }

    /**
     * Get all the Teams the current user is a member of.
     *
     * @param user Current logged in user.
     * @return A Collection of Teams of which the current User is a member
     */
    @JsonView(View.Team.class)
    @GetMapping("/teams")
    public Collection<Team> getCurrentTeams(@AuthenticationPrincipal User user) {
        return teamService.getTeamsByMemberEmail(user.getEmail());
    }

    @GetMapping("/teams/invites")
    public List<TeamInviteResponse> getOpenInvites(@AuthenticationPrincipal User user) {
        return teamService.findTeamInvitesByEmail(user.getEmail());
    }

    /**
     * Get all Orders that the current User created. This doesn't include expired orders. This will be a Collection with
     * size 0 or 1 of the majority, but it can contain more orders.
     *
     * @param user Current logged in user.
     * @return A collection of Orders of the current User.
     */
    @JsonView(View.OrderOverview.class)
    @GetMapping("/orders")
    public Collection<Order> getAllOrders(@AuthenticationPrincipal User user) {
        return orderService.findOrdersByEmail(user.getEmail());
    }

    /**
     * Get the tickets of the currently logged in user. All the tickets owned by this user will be returned.
     *
     * @param user Current logged in user.
     * @return The current owned tickets, if any exist
     */
    @GetMapping("/tickets")
    public Collection<Ticket> getAllTickets(@AuthenticationPrincipal User user) {
        return ticketService.findValidTicketsByOwnerEmail(user.getEmail());
    }

    /**
     * Get the current open order include expired orders. A User van only have one open order.
     *
     * @param user Current logged in user.
     * @return The current open order, if any exist
     */
    @GetMapping("/orders/open")
    public List<Order> getOpenOrder(@AuthenticationPrincipal User user) {
        return orderService.getOpenOrders(user.getEmail());
    }

    /**
     * Get the seats of the current user
     *
     * @param user Current logged in user.
     * @return Returns a list of reserved seats by the user
     */
    @GetMapping("/seat")
    public List<Seat> getCurrentUserSeat(@AuthenticationPrincipal User user) {
        return seatService.getSeatsByEmail(user.getEmail());
    }
}
