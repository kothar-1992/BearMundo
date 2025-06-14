package com.bearmod.model;

/**
 * User model class
 */
public class User {
    private String id;
    private String username;
    private String email;
    private boolean premium;
    
    /**
     * Default constructor
     */
    public User() {
    }
    
    /**
     * Constructor with parameters
     * 
     * @param id User ID
     * @param username Username
     * @param email Email address
     * @param premium Premium status
     */
    public User(String id, String username, String email, boolean premium) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.premium = premium;
    }
    
    // Getters and setters
    
    public String getId() {
        return id;
    }
    
    public void setId(String id) {
        this.id = id;
    }
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getEmail() {
        return email;
    }
    
    public void setEmail(String email) {
        this.email = email;
    }
    
    public boolean isPremium() {
        return premium;
    }
    
    public void setPremium(boolean premium) {
        this.premium = premium;
    }
    
    @Override
    public String toString() {
        return "User{" +
                "id='" + id + '\'' +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", premium=" + premium +
                '}';
    }
}
