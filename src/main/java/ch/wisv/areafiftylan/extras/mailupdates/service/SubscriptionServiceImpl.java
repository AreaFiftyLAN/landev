/*
 *  Copyright (c) 2017  W.I.S.V. 'Christiaan Huygens'
 *
 *      This program is free software: you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation, either version 3 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package ch.wisv.areafiftylan.extras.mailupdates.service;

import ch.wisv.areafiftylan.exception.SubscriptionNotFoundException;
import ch.wisv.areafiftylan.extras.mailupdates.model.Subscription;
import ch.wisv.areafiftylan.extras.mailupdates.model.SubscriptionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Collection;

/**
 * @author Jurriaan Den Toonder Created on 23-10-17
 */
@Service
public class SubscriptionServiceImpl implements SubscriptionService {
  private final SubscriptionRepository subscriptionRepository;

  @Autowired
  public SubscriptionServiceImpl(SubscriptionRepository subscriptionRepository) {
    this.subscriptionRepository = subscriptionRepository;
  }

  @Override
  public Subscription addSubscription(String email) {
    Subscription newSubscription = new Subscription(email);
    return subscriptionRepository.saveAndFlush(newSubscription);
  }

  @Override
  public void removeSubscription(String email) {
    Subscription subscription = subscriptionRepository
            .findByEmail(email)
            .orElseThrow(() -> new SubscriptionNotFoundException("Could not find subscription with email " + email));
    subscriptionRepository.delete(subscription.getId());
  }

  @Override
  public Collection<Subscription> getSubscriptions() {
    return subscriptionRepository.findAll();
  }
}
