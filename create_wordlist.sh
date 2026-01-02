#!/bin/bash

# Define the word list (Clean, 4-6 letters, Title Case)
words=(
    "Area" "Army" "Baby" "Back" "Ball" "Band" "Bank" "Base" "Bear" "Beat"
    "Bell" "Belt" "Best" "Bird" "Blue" "Boat" "Body" "Bond" "Bone" "Book"
    "Boom" "Born" "Boss" "Bowl" "Bulk" "Burn" "Bush" "Busy" "Call" "Calm"
    "Camp" "Card" "Care" "Case" "Cash" "Cast" "Cell" "Chat" "Chip" "City"
    "Club" "Coal" "Coat" "Code" "Cold" "Come" "Cook" "Cool" "Copy" "Core"
    "Cost" "Crew" "Crop" "Dark" "Data" "Date" "Deal" "Debt" "Deep" "Desk"
    "Disc" "Dish" "Disk" "Door" "Down" "Draw" "Drop" "Drug" "Dual" "Dust"
    "Duty" "Each" "Earn" "Ease" "East" "Easy" "Edge" "Edit" "Else" "Face"
    "Fact" "Fair" "Fall" "Farm" "Fast" "Fate" "Fear" "Feed" "Feel" "File"
    "Fill" "Film" "Find" "Fine" "Fire" "Firm" "Fish" "Flat" "Flow" "Food"
    "Foot" "Ford" "Form" "Fort" "Four" "Free" "From" "Fuel" "Full" "Fund"
    "Gain" "Game" "Gate" "Gear" "Gift" "Girl" "Give" "Glad" "Goal" "Goat"
    "Gold" "Golf" "Good" "Gray" "Grey" "Grow" "Hair" "Half" "Hall" "Hand"
    "Hang" "Hard" "Head" "Hear" "Heat" "Help" "Here" "Hero" "High" "Hill"
    "Hold" "Home" "Hope" "Host" "Hour" "Huge" "Hunt" "Hurt" "Idea" "Inch"
    "Into" "Iron" "Item" "Jack" "Jazz" "Join" "Jump" "Jury" "Just" "Keen"
    "Keep" "Kick" "Kill" "Kind" "King" "Knee" "Know" "Lack" "Lady" "Lake"
    "Land" "Lane" "Last" "Late" "Lead" "Left" "Less" "Life" "Lift" "Like"
    "Line" "Link" "List" "Live" "Load" "Loan" "Lock" "Logo" "Long" "Look"
    "Loop" "Lord" "Loss" "Lost" "Love" "Luck" "Made" "Mail" "Main" "Make"
    "Male" "Many" "Mark" "Mask" "Mass" "Math" "Meal" "Mean" "Meat" "Meet"
    "Menu" "Mile" "Milk" "Mind" "Mine" "Miss" "Mode" "Mood" "Moon" "More"
    "Most" "Move" "Much" "Must" "Name" "Near" "Neck" "Need" "News" "Next"
    "Nice" "Node" "None" "Note" "Noun" "Null" "Okay" "Once" "Only" "Open"
    "Oral" "Over" "Pack" "Page" "Pain" "Pair" "Palm" "Park" "Part" "Pass"
    "Past" "Path" "Peak" "Peer" "Pipe" "Plan" "Play" "Plot" "Plug" "Plus"
    "Poll" "Pool" "Poor" "Port" "Post" "Pull" "Pure" "Push" "Race" "Rail"
    "Rain" "Rank" "Rare" "Rate" "Read" "Real" "Rear" "Rely" "Rent" "Rest"
    "Rice" "Rich" "Ride" "Ring" "Rise" "Risk" "Road" "Rock" "Role" "Roll"
    "Roof" "Room" "Root" "Rose" "Rule" "Rush" "Safe" "Sale" "Salt" "Same"
    "Sand" "Save" "Seat" "Seed" "Seek" "Seem" "Self" "Sell" "Send" "Sent"
    "Set" "Shape" "Share" "Sharp" "Ship" "Shoe" "Shop" "Shot" "Show" "Shut"
    "Side" "Sign" "Site" "Size" "Skin" "Slip" "Slow" "Snow" "Soft" "Soil"
    "Sold" "Sole" "Some" "Song" "Soon" "Sort" "Soul" "Soup" "Spot" "Star"
    "Stay" "Step" "Stop" "Such" "Suit" "Sure" "Swim" "Take" "Talk" "Tall"
    "Tank" "Tape" "Task" "Team" "Tech" "Tell" "Term" "Test" "Text" "Than"
    "That" "Them" "Then" "This" "Tide" "Time" "Tiny" "Tour" "Town" "Tree"
    "Trip" "True" "Tube" "Turn" "Twin" "Type" "Unit" "Upon" "User" "Vary"
    "Vast" "Very" "Vice" "View" "Vote" "Wage" "Wait" "Walk" "Wall" "Want"
    "Ward" "Warm" "Wash" "Wave" "Week" "Well" "West" "What" "When" "Wide"
    "Wife" "Wild" "Will" "Wind" "Wine" "Wing" "Wire" "Wise" "Wish" "With"
    "Wolf" "Wood" "Word" "Work" "Yard" "Year" "Zero" "Zone" "Zoom"
)

# Get the directory where the script is running
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DICT_DIR="$DIR/Dictionaries"

# Create directory if it doesn't exist
if [ ! -d "$DICT_DIR" ]; then
    mkdir -p "$DICT_DIR"
fi

# Define output file
FILE="$DICT_DIR/words.txt"

# Write words to file (one per line)
printf "%s\n" "${words[@]}" > "$FILE"

echo -e "\033[0;32mSuccess! Created $FILE with ${#words[@]} words.\033[0m"