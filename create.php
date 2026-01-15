<?php
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  account_type ENUM('admin','secretary','farmer') NOT NULL DEFAULT 'farmer'
);
?>