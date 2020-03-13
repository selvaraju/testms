package pl.piomin.microservices.auth.dao;

import pl.piomin.microservices.auth.user.ARUser;

public class User {

    private String userName;

    private String firstName;

    private  String latsName;

    private  String email;

    private ARUser.Role role;

    private  String license;

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLatsName() {
        return latsName;
    }

    public void setLatsName(String latsName) {
        this.latsName = latsName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public ARUser.Role getRole() {
        return role;
    }

    public void setRole(ARUser.Role role) {
        this.role = role;
    }

    public String getLicense() {
        return license;
    }

    public void setLicense(String license) {
        this.license = license;
    }
}
