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

package ch.wisv.areafiftylan.users.model;

import ch.wisv.areafiftylan.utils.view.View;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.io.Serializable;
import java.util.Calendar;

@Entity
public class Profile implements Serializable {

    public String firstName;
    public String lastName;

    @JsonView(View.Public.class)
    public String displayName;

    public Calendar birthday;

    public Gender gender;
    public String address;
    public String zipcode;
    public String city;
    public String phoneNumber;
    public String notes;

    @Id
    @GeneratedValue
    private Long id;

    Profile() {

    }

    public Profile(String firstName, String lastName, String displayName, Calendar birthday, Gender gender, String address, String zipcode,
                   String city, String phoneNumber, String notes) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.displayName = displayName;
        this.birthday = birthday;
        this.gender = gender;
        this.address = address;
        this.zipcode = zipcode;
        this.city = city;
        this.phoneNumber = phoneNumber;
        this.notes = notes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Profile)) {
            return false;
        }

        Profile profile = (Profile) o;

        if (firstName != null ? !firstName.equals(profile.firstName) : profile.firstName != null) {
            return false;
        }
        if (lastName != null ? !lastName.equals(profile.lastName) : profile.lastName != null) {
            return false;
        }
        if (displayName != null ? !displayName.equals(profile.displayName) : profile.displayName != null) {
            return false;
        }
        if (gender != profile.gender) {
            return false;
        }
        if (address != null ? !address.equals(profile.address) : profile.address != null) {
            return false;
        }
        if (zipcode != null ? !zipcode.equals(profile.zipcode) : profile.zipcode != null) {
            return false;
        }
        if (city != null ? !city.equals(profile.city) : profile.city != null) {
            return false;
        }
        if (phoneNumber != null ? !phoneNumber.equals(profile.phoneNumber) : profile.phoneNumber != null) {
            return false;
        }
        return !(notes != null ? !notes.equals(profile.notes) : profile.notes != null);

    }

    @Override
    public int hashCode() {
        int result = firstName != null ? firstName.hashCode() : 0;
        result = 31 * result + (lastName != null ? lastName.hashCode() : 0);
        result = 31 * result + (displayName != null ? displayName.hashCode() : 0);
        result = 31 * result + (birthday != null ? birthday.hashCode() : 0);
        result = 31 * result + (gender != null ? gender.hashCode() : 0);
        result = 31 * result + (address != null ? address.hashCode() : 0);
        result = 31 * result + (zipcode != null ? zipcode.hashCode() : 0);
        result = 31 * result + (city != null ? city.hashCode() : 0);
        result = 31 * result + (phoneNumber != null ? phoneNumber.hashCode() : 0);
        result = 31 * result + (notes != null ? notes.hashCode() : 0);
        return result;
    }

    public Calendar getBirthday() {
        return birthday;
    }

    public void setBirthday(Calendar birthday) {
        this.birthday = birthday;
    }

    public Gender getGender() {
        return gender;
    }

    public void setGender(Gender gender) {
        this.gender = gender;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getZipcode() {
        return zipcode;
    }

    public void setZipcode(String zipcode) {
        this.zipcode = zipcode;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public void setAllFields(String firstName, String lastName, String displayName, Calendar birthday, Gender gender, String address,
                             String zipcode, String city, String phoneNumber, String notes) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.displayName = displayName;
        this.birthday = birthday;
        this.gender = gender;
        this.address = address;
        this.zipcode = zipcode;
        this.city = city;
        this.phoneNumber = phoneNumber;
        this.notes = notes;
    }
}