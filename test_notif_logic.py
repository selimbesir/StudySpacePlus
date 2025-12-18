import datetime
from datetime import timedelta

# Mock Objects
class MockRes:
    def __init__(self, id, space_name, time_slot, date_str):
        self.id = id
        self.space_name = space_name
        self.time_slot = time_slot
        self.date = date_str
        self.user_id = 1

class MockUser:
    def __init__(self):
        self.id = 1

# Simulation Function
def simulate_check(reservations, current_time_str):
    now = datetime.datetime.strptime(current_time_str, "%Y-%m-%d %H:%M:%S")
    
    print(f"\n--- Simulation at {now} ---")
    
    notified_start = set()
    notified_end = set()
    
    for res in reservations:
        # ORIGINAL LOGIC FROM app.py
        
        res_date = datetime.datetime.strptime(res.date, "%Y-%m-%d").date()
        start_str = res.time_slot.split(' - ')[0]
        end_str = res.time_slot.split(' - ')[1]
        
        res_start = datetime.datetime.combine(res_date, datetime.datetime.strptime(start_str, "%H:%M").time())
        res_end = datetime.datetime.combine(res_date, datetime.datetime.strptime(end_str, "%H:%M").time())
        
        # --- Potential Fix for Midnight ---
        # if res_end < res_start:
        #    res_end += timedelta(days=1)
        # ----------------------------------

        # Check for 25 minutes before start
        time_until_start = (res_start - now).total_seconds()
        start_key = f"start_{res.id}"
        
        # 25 minutes = 1500 seconds, check within a 20-second window (1490-1510)
        if 1490 <= time_until_start <= 1510:
            print(f"[START NOTIF] Res {res.id} ({res.time_slot}) starts in {time_until_start/60:.2f} mins")
        
        # Check for 25 minutes before end
        time_until_end = (res_end - now).total_seconds()
        end_key = f"end_{res.id}"
        
        if 1490 <= time_until_end <= 1510:
             print(f"[END NOTIF] Res {res.id} ({res.time_slot}) ends in {time_until_end/60:.2f} mins")


# Scenario 1: Single Reservation, 25 mins before start
print("SCENARIO 1: Single Reservation 09:00-10:00. Time is 08:35.")
res1 = MockRes(1, "Room A", "09:00 - 10:00", "2023-10-25")
simulate_check([res1], "2023-10-25 08:35:00")

# Scenario 2: Back-to-Back Reservations.
# Res A: 09:00-10:00 (Ending soon)
# Res B: 10:00-11:00 (Starting soon)
# Time is 09:35
print("\nSCENARIO 2: Back-to-Back 09:00-10:00 and 10:00-11:00. Time is 09:35.")
res2 = MockRes(2, "Room A", "09:00 - 10:00", "2023-10-25")
res3 = MockRes(3, "Room A", "10:00 - 11:00", "2023-10-25")
simulate_check([res2, res3], "2023-10-25 09:35:00")

# Scenario 3: Midnight Slot 23:00 - 00:00.
print("\nSCENARIO 3: Midnight Slot 23:00-00:00. Time is 22:35 (25 min before start).")
res4 = MockRes(4, "Room B", "23:00 - 00:00", "2023-10-25")
simulate_check([res4], "2023-10-25 22:35:00")
