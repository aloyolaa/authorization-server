package com.aloyolaa.authorizationserver.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.Hibernate;

import java.util.Objects;

@Getter
@Setter
@Entity
@Table(name = "authority", uniqueConstraints = {
        @UniqueConstraint(name = "uc_authority_name", columnNames = {"name"})
})
public class Authority extends BaseEntity {
    @Column(name = "name", nullable = false, length = 30)
    private String name;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || Hibernate.getClass(this) != Hibernate.getClass(o)) return false;
        Authority authority = (Authority) o;
        return getId() != null && Objects.equals(getId(), authority.getId());
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}