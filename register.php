<?php
    try 
    { 
        $conn = new mysqli('http://odyssey.servegame.com','dummy_register', 'wrz1000scheme9999!@', 'auth'); 
    } 
    catch(mysqli_sql_exception $e) 
    {
        echo 'Mysql connection error, wrong configuration!';
    }
    
    if ($conn->connect_error) {
        die("Connection failed!");
    } 
    else
    {
        if(!empty($_POST['uu']) && !empty($_POST['pp']) &&!empty($_POST['ee']))
        {
            // get parameters
            $username_input = $_POST['uu'];
            $password_input = $_POST['pp'];
            $email_input    = $_POST['ee'];
            
            // convert password to sha1
            $passhash = sha1(strtoupper($username_input.':'.$password_input));
            
            if (strlen($username_input) < 6 or strlen($username_input) > 16)
            {
                echo 'Account must be between 6 and 10 characters';
                return;
            }
            
            if (strlen($password_input) < 6)
            {
                echo 'Password must be atleast 6 characters';
                return;
            }
            
            $stmt = $stmt = $conn->prepare('INSERT INTO account (username, sha_pass_hash, email) VALUES (?, ?, ?);');
            
            $stmt->bind_param('sss', $username_input, $passhash, $email_input);
            
            $stmt->execute();
            
            if ($stmt->affected_rows > 0) 
                echo 'Account registered successfully.';
            else 
                echo 'Account already exists!';
            
            // vip 1 free
            $stmt = $stmt = $conn->prepare('INSERT INTO account_vip (id, vip_level, no_due, active) SELECT id, 1, 1, 1 FROM account WHERE username=?;');
            
            $stmt->bind_param('s', $username_input);
            
            $stmt->execute();
        }
    }
    
    mysqli_close($conn);
?>
