     import sqlite3

     # Connect to the database
     conn = sqlite3.connect('jonyo_school.db')
     c = conn.cursor()

     # Update term values
     c.execute("UPDATE marks SET term = 'Term 1' WHERE term = 'term 1'")
     c.execute("UPDATE marks SET term = 'Term 2' WHERE term = 'term 2'")
     c.execute("UPDATE marks SET term = 'Term 3' WHERE term = 'term 3'")

     # Update exam_type values
     c.execute("UPDATE marks SET exam_type = 'Mid Term' WHERE exam_type = 'mid-term'")
     c.execute("UPDATE marks SET exam_type = 'End Term' WHERE exam_type = 'end-term'")

     # Commit the changes
     conn.commit()

     # Verify updates
     c.execute("SELECT DISTINCT term, exam_type FROM marks")
     print("Updated term and exam_type values:", c.fetchall())  # Should show: [('Term 1', 'Mid Term'), ('Term 2', 'End Term'), ...]

     # Close the connection
     conn.close()

     print("Database update completed successfully.")