package ch.wisv.areafiftylan.service;

import ch.wisv.areafiftylan.model.Ticket;
import ch.wisv.areafiftylan.model.relations.RFIDLink;

import java.util.Collection;

/**
 * Created by beer on 5-5-16.
 */
public interface RFIDService {
    Collection<RFIDLink> getAllRFIDLinks();

    Long getTicketIdByRFID(String rfid);

    String getRFIDByTicketId(Long ticketId);

    boolean isRFIDUsed(String rfid);

    void addRFIDLink(RFIDLink link);
}