print("Welcome to my quiz!")

playing = input("Do you want to play? ")
print(playing)
if playing.lower() != "yes" :
    quit()

print("Okay! Let's play =)")
score = 0

answer = input("What is the capital of France? ")
if answer.lower() == "paris":
    print('Correct!')
    score += 1
else: print('Incorrect!')

answer = input("What is the largest planet in our solar system? ").lower()
if answer == "jupiter":
    print('Correct!')
    score += 1
else: print('Incorrect!')

answer = input("What is the smallest country in the world? ")
if answer.lower() == "vatican city":
    print('Correct!')
    score += 1
else: print('Incorrect!')

print("You got " + str(score) + " questions correct! Thanks for playing!")
print("You got " + str(score/3 * 100) + "%.")