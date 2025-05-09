             ##################################
             ###### !!! Start Here !!! ########
             ##################################   
             

     #####################################################
     ########   Complete the following 5 steps: ##########
     #####################################################

############
## STEP 1 ##
############

   # Query 1 listed below represents the database request that is intended to be made when a user inputs in their id number and presses "submit" from the webpage. After pressing submit the webpage will display the users First Name and Last Name.
   # To view an image on how the webpage works, access the following webpage: https://tinyurl.com/y3flaefm
   # Between the single green quotes below, place the number 1 which represents the user id number.  Note that this number 1 indicates what the user inputted in on the form field from the webpage.
   # Press the RUN button on the top left of this page, and view the results below. This should display the the first name and last name in two separate columns.
 
 
                      # Query 1:
                     
               # MODIFY THE QUERY BELOW #

select first_name, last_name from users where user_id = '1'


;
########################################################

############
## STEP 2 ##
############

   # Now you are tasked with changing the user input from the number 1, to an input which will display all the data in the data.
   # This will represent the payload that a malicious user could potentially  input and run from the webpage to cause unintended consequences.
   # Using the query number 2 below, use the most common "always true" payload covered in the lesson and place it between the green single quotes.
   # Hint: View your class slides for this common "always true" Payload
   # Press the RUN button again on the top left of this page, and view the results below for Query #2. Note that you may need to scroll down to see your results for Query #2
   
   
                       # Query 2:
                       
               # MODIFY THE QUERY BELOW #

select first_name, last_name from users where user_id = '1 OR "1 = 1"'


;
########################################################

############
## STEP 3 ##
############

   # Now you are tasked with changing the user input from the most common always true value payload, to a DIFFERENT always true value. <Hint: try using  'dog' = 'dog'>
   # This will represent a similar but different payload of what a malicious user could potentially input from the webpage to cause unintended consequences. Other payloads are often used in case the most common "always true" payload gets blocked.
   # Using the query number 3 below, change the user input from  most common always true payload to another always true payload of your choice.
   # Press the RUN button again on the top left of this page, and view the results below for Query #3, confirm your results match the results from Query #2. Note that you may need to scroll down to see your results for Query #3
   
   
                       # Query 3:
                       
                 # MODIFY THE QUERY BELOW #   

select first_name, last_name from users where user_id = '1 OR "dog = dog"'


;
########################################################

##################
## BONUS STEP 4 ##
##################

   # Now you are tasked with changing the user input to see if you can pull data from other fields not originally intended to be displayed to the user
   # For this step, design a payload using the  UNION command in Query #4 below, to see if you can pull information from the password field.
   # Hint: Refer to the following page to see how to use a union command to pull data from other fields: https://www.w3schools.com/sql/sql_union.asp
   # Press the RUN button again on the top left of this page, and see if you were able to display the hashed passwords for the users. Note that you may need to scroll down to see your results for Query #4
   
   
                       # Query 4:
                       
                # MODIFY THE QUERY BELOW #     

select first_name, last_name from users where user_id = '1'
UNION
select password, '' from users where user_id='1'

;
########################################################

###################
## BONUS: STEP 5 ##
###################

   # You are tasked with changing the user input to see if you can pull 3 data fields using one payload (first_name,  last_name, password)
   # For this step, design a payload using the  UNION command with a new command called CONCAT in Query #5 below
   # Note: You will need to research online how to use CONCAT to combine fields, refer to the following page for assistance: https://www.w3schools.com/sql/func_sqlserver_concat.asp
   # Press the RUN button again on the top left of this page, and see if you were able to display all four fields with a single payload. Note that you may need to scroll down to see your results for Query #5
   
   
                       # Query 5:
                    
                # MODIFY THE QUERY BELOW #    

select first_name, last_name from users where user_id = '1'
union
select concat(first_name, '','last_name',':', password), '' from users where user_id = '1'


;