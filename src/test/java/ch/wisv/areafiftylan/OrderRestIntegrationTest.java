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

import ch.wisv.areafiftylan.products.model.Ticket;
import ch.wisv.areafiftylan.products.model.order.Order;
import ch.wisv.areafiftylan.products.service.repository.OrderRepository;
import ch.wisv.areafiftylan.products.service.repository.TicketRepository;
import ch.wisv.areafiftylan.users.model.User;
import io.restassured.http.ContentType;
import org.apache.http.HttpStatus;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static io.restassured.RestAssured.when;
import static org.hamcrest.Matchers.*;


public class OrderRestIntegrationTest extends XAuthIntegrationTest {

    @Autowired
    protected OrderRepository orderRepository;

    @Autowired
    private TicketRepository ticketRepository;

    @Value("${a5l.ticketLimit}")
    private int TICKET_LIMIT;

    private final String ORDER_ENDPOINT = "/orders/";

    private Order addOrderForUser(User user) {
        Ticket ticket = ticketRepository.save(new Ticket(
                ticketTypeRepository.findByName(TEST_TICKET).orElseThrow(IllegalArgumentException::new)));
        Order order = new Order(user);
        order.addTicket(ticket);
        return orderRepository.save(order);

    }

    private Order insertAnonOrder() {
        Order order = new Order();
        Ticket ticket = ticketRepository.save(new Ticket(
                ticketTypeRepository.findByName(TEST_TICKET).orElseThrow(IllegalArgumentException::new)));
        order.addTicket(ticket);
        return orderRepository.save(order);
    }

    @Test
    public void testGetAllOrdersAnon() {
        insertAnonOrder();

        //@formatter:off
        when().
            get(ORDER_ENDPOINT).
        then().
            statusCode(HttpStatus.SC_FORBIDDEN).body("message", containsString("denied"));
        //@formatter:on
    }

    @Test
    public void testGetAllOrdersAsUser() {
        insertAnonOrder();

        User user = createUser();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            get(ORDER_ENDPOINT).
        then().
            statusCode(HttpStatus.SC_FORBIDDEN).body("message", containsString("denied"));
        //@formatter:on
    }

    @Test
    public void testGetAllOrdersAsAdmin() {
        insertAnonOrder();

        User admin = createUser(true);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            get(ORDER_ENDPOINT).
        then().
            statusCode(HttpStatus.SC_OK).
            body("$", hasSize(Long.valueOf(orderRepository.count()).intValue()));
        //@formatter:on
    }

    @Test
    public void testCreateAnonOrder() {
        Map<String, Object> order = new HashMap<>();
        List<String> options = Arrays.asList(CH_MEMBER, PICKUP_SERVICE);
        order.put("type", TEST_TICKET);
        order.put("options", options);

        //@formatter:off
        given().
        when().
            body(order).contentType(ContentType.JSON).
            post(ORDER_ENDPOINT)
        .then().
            statusCode(HttpStatus.SC_CREATED).
            body("object.user", is(nullValue())).
            body("object.status", is("ANONYMOUS")).
            body("object.tickets", hasSize(1)).
            body("object.tickets.type.name", hasItem(is(TEST_TICKET))).
            body("object.tickets.type.text", anything()).
            body("object.tickets.enabledOptions.name", hasItem(hasItems(CH_MEMBER, PICKUP_SERVICE))).
            body("object.amount",equalTo(27.5F));
        //@formatter:on
    }

    @Test
    public void testCreateOrderAsUser() {
        Map<String, Object> order = new HashMap<>();
        List<String> options = Arrays.asList(CH_MEMBER, PICKUP_SERVICE);
        order.put("type", TEST_TICKET);
        order.put("options", options);
        User user = createUser();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(order).contentType(ContentType.JSON).
            post(ORDER_ENDPOINT)
        .then().
            statusCode(HttpStatus.SC_CREATED).
            body("object.user", is(nullValue())).
            body("object.status", is("ANONYMOUS")).
            body("object.tickets", hasSize(1)).
            body("object.tickets.type.name", hasItem(is(TEST_TICKET))).
            body("object.tickets.type.text", anything()).
            body("object.tickets.enabledOptions.name", hasItem(hasItems(CH_MEMBER, PICKUP_SERVICE))).
            body("object.amount",equalTo(27.5F));
        //@formatter:on
    }

    @Test
    public void testAddTicketToAnonOrder() {
        Order order = insertAnonOrder();

        Map<String, Object> orderDTO = new HashMap<>();
        List<String> options = Arrays.asList(CH_MEMBER, PICKUP_SERVICE);
        orderDTO.put("type", TEST_TICKET);
        orderDTO.put("options", options);

        //@formatter:off
        given().
        when().
            body(orderDTO).contentType(ContentType.JSON).
            post(ORDER_ENDPOINT + order.getId())
        .then().
            statusCode(HttpStatus.SC_OK).
            body("object.user", is(nullValue())).
            body("object.status", is("ANONYMOUS")).
            body("object.tickets", hasSize(2)).
            body("object.tickets.type.name", hasItems(TEST_TICKET, TEST_TICKET)).
            body("object.tickets.enabledOptions.name", hasItem(hasItems(CH_MEMBER, PICKUP_SERVICE))).
            body("object.amount",equalTo(57.5F));
        //@formatter:on
    }

    @Test
    public void testAddTicketToAssignedOrderAnon() {
        User user = createUser();
        Order order = addOrderForUser(user);

        Map<String, Object> orderDTO = new HashMap<>();
        List<String> options = Arrays.asList(CH_MEMBER, PICKUP_SERVICE);
        orderDTO.put("type", TEST_TICKET);
        orderDTO.put("options", options);

        //@formatter:off
        given().
        when().
            body(orderDTO).contentType(ContentType.JSON).
            post(ORDER_ENDPOINT + order.getId())
        .then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testAddTicketToAssignedOrderAsUser() {
        User user = createUser();
        Order order = addOrderForUser(user);

        Map<String, Object> orderDTO = new HashMap<>();
        List<String> options = Arrays.asList(CH_MEMBER, PICKUP_SERVICE);
        orderDTO.put("type", TEST_TICKET);
        orderDTO.put("options", options);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            body(orderDTO).contentType(ContentType.JSON).
            post(ORDER_ENDPOINT + order.getId())
        .then().
            statusCode(HttpStatus.SC_OK).
            body("object.user.username", is(user.getUsername())).
            body("object.status", is("ASSIGNED")).
            body("object.tickets", hasSize(2)).
            body("object.tickets.type.name", hasItems(TEST_TICKET, TEST_TICKET)).
            body("object.tickets.enabledOptions.name", hasItem(hasItems(CH_MEMBER, PICKUP_SERVICE))).
            body("object.amount",equalTo(57.5F));
        //@formatter:on
    }

    @Test
    public void testAddTicketToAssignedOrderAsWrongUser() {
        User user = createUser();
        User user2 = createUser();
        Order order = addOrderForUser(user);

        Map<String, Object> orderDTO = new HashMap<>();
        List<String> options = Arrays.asList(CH_MEMBER, PICKUP_SERVICE);
        orderDTO.put("type", TEST_TICKET);
        orderDTO.put("options", options);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user2)).
        when().
            body(orderDTO).contentType(ContentType.JSON).
            post(ORDER_ENDPOINT + order.getId())
        .then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testAddTicketToAssignedOrderAsAdmin() {
        User user = createUser();
        User admin = createUser(true);
        Order order = addOrderForUser(user);

        Map<String, Object> orderDTO = new HashMap<>();
        List<String> options = Arrays.asList(CH_MEMBER, PICKUP_SERVICE);
        orderDTO.put("type", TEST_TICKET);
        orderDTO.put("options", options);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            body(orderDTO).contentType(ContentType.JSON).
            post(ORDER_ENDPOINT + order.getId())
        .then().
            statusCode(HttpStatus.SC_OK).
            body("object.user.username", is(user.getUsername())).
            body("object.status", is("ASSIGNED")).
            body("object.tickets", hasSize(2)).
            body("object.tickets.type.name", hasItems(TEST_TICKET, TEST_TICKET)).
            body("object.tickets.enabledOptions.name", hasItem(hasItems(CH_MEMBER, PICKUP_SERVICE))).
            body("object.amount",equalTo(57.5F));
        //@formatter:on
    }

    @Test
    public void testGetAnonOrderAsAnon() {
        Order order = insertAnonOrder();

        //@formatter:off
         when().
            get(ORDER_ENDPOINT + order.getId()).
        then().
            statusCode(HttpStatus.SC_OK).
            body("user", is(nullValue())).
            body("status", is("ANONYMOUS")).
            body("tickets", hasSize(1)).
            body("tickets.type.name", hasItem(is(TEST_TICKET))).
            body("tickets.type.text", anything()).
            body("tickets.enabledOptions.name", hasItem(emptyIterable())).
            body("amount",equalTo(30F));
         //@formatter:on
    }

    @Test
    public void testGetAnonOrderAsUser() {
        Order order = insertAnonOrder();
        User user = createUser();

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            get(ORDER_ENDPOINT + order.getId()).
        then().
            statusCode(HttpStatus.SC_OK).
            body("user", is(nullValue())).
            body("status", is("ANONYMOUS")).
            body("tickets", hasSize(1)).
            body("tickets.type.name", hasItem(is(TEST_TICKET))).
            body("tickets.type.text", anything()).
            body("tickets.enabledOptions.name", hasItem(emptyIterable())).
            body("amount",equalTo(30F));
         //@formatter:on
    }

    @Test
    public void testGetAnonOrderAsAdmin() {
        Order order = insertAnonOrder();
        User user = createUser(true);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            get(ORDER_ENDPOINT + order.getId()).
        then().
            statusCode(HttpStatus.SC_OK).
            body("user", is(nullValue())).
            body("status", is("ANONYMOUS")).
            body("tickets", hasSize(1)).
            body("tickets.type.name", hasItem(is(TEST_TICKET))).
            body("tickets.type.text", anything()).
            body("tickets.enabledOptions", hasItem(emptyIterable())).
            body("amount",equalTo(30F));
         //@formatter:on
    }

    @Test
    public void testGetAssignedOrderAsAnon() {
        User user = createUser();
        Order order = addOrderForUser(user);

        //@formatter:off
        when().
            get(ORDER_ENDPOINT + order.getId())
        .then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testGetAssignedOrderAsUser() {
        User user = createUser();
        Order order = addOrderForUser(user);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user)).
        when().
            get(ORDER_ENDPOINT + order.getId())
        .then().
            statusCode(HttpStatus.SC_OK).
            body("user.username", is(user.getUsername())).
            body("status", is("ASSIGNED")).
            body("tickets", hasSize(1)).
            body("tickets.type.name", hasItem(is(TEST_TICKET))).
            body("tickets.type.text", anything()).
            body("tickets.enabledOptions.name", hasItem(emptyIterable())).
            body("amount",equalTo(30F));
        //@formatter:on
    }

    @Test
    public void testGetAssignedOrderAsWrongUser() {
        User user = createUser();
        User user2 = createUser();
        Order order = addOrderForUser(user);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(user2)).
        when().
            get(ORDER_ENDPOINT + order.getId())
        .then().
            statusCode(HttpStatus.SC_FORBIDDEN);
        //@formatter:on
    }

    @Test
    public void testGetAssignedOrderAsAdmin() {
        User user = createUser();
        User admin = createUser(true);
        Order order = addOrderForUser(user);

        //@formatter:off
        given().
            header(getXAuthTokenHeaderForUser(admin)).
        when().
            get(ORDER_ENDPOINT + order.getId())
        .then().
            statusCode(HttpStatus.SC_OK).
            body("user.username", is(user.getUsername())).
            body("status", is("ASSIGNED")).
            body("tickets", hasSize(1)).
            body("tickets.type.name", hasItem(is(TEST_TICKET))).
            body("tickets.type.text", anything()).
            body("tickets.enabledOptions", hasItem(emptyIterable())).
            body("amount",equalTo(30F));
        //@formatter:on
    }

    @Test
    public void testAssignAnonOrderAsAnon() {

    }

    @Test
    public void testAssignAnonOrderAsUser() {

    }

    @Test
    public void testAssignAssignedOrderAsAnon() {

    }

    @Test
    public void testAssignAssignedOrderAsUser() {

    }

    @Test
    public void testAssignAssignedOrderAsAdmin() {

    }

    @Test
    public void testCheckoutAssignedOrderAsAnon() {

    }

    @Test
    public void testCheckoutAssignedOrderAsUser() {

    }

    @Test
    public void testCheckoutAssignedOrderWrongUser() {

    }

    @Test
    public void testCheckoutAssignedOrderAsAdmin() {

    }

    @Test
    public void testCheckoutAnonOrder() {

    }

    @Test
    public void testApproveOrderAsAnon() {

    }

    @Test
    public void testApproveOrderAsUser() {

    }

    @Test
    public void testApproveOrderAsAdmin() {

    }


}