# Security Specification (TDD) for PCM Plus Academy

## 1. Data Invariants

- **User Profiles (`/users/{userId}`)**:
  - A user profile must have its Firestore document ID match the user's Auth UID (`request.auth.uid`).
  - Users can read and write only their own profile details.
  - Role mutation (`student` to `admin`) is strictly forbidden for regular users. Only existing admins (validated on the backend / through `users/$(uid).role == "admin"`) can promote roles.
  - The `email` and `createdAt` properties are immutable once created.

- **Admin-Authored Resources (`/courses`, `/notes`, `/tests`, `/currentAffairs`, `/blogs`, `/notifications`)**:
  - Read access is allowed for any authenticated user.
  - Mutation access (Create, Update, Delete) is strictly restricted to authenticated Admin users whose role in `/users/{userId}` is `"admin"`.

- **MCQ Test Results (`/testResults/{resultId}`)**:
  - Any authenticated student can save their own test results (where `userId == request.auth.uid`).
  - Read access is restricted to the owner of the test result or an Administrator.
  - Test results must be immutable once created (no update/delete by students).

- **System Alerts & Notifications (`/notifications/{id}`)**:
  - General read access to view notifications.
  - Write, modify, and delete access is locked strictly to Administrators.

---

## 2. The "Dirty Dozen" Attack Payloads (Simulated Penetration Scenarios)

1. **Self-Escalation**: User `student_123` attempts to create an admin profile with `"role": "admin"`.
2. **Profile Theft**: User `student_123` attempts to write/overwrite the profile document of `student_456`.
3. **Ghost Course Injection**: User `student_123` attempts to write a fake course package directly into `/courses/fake_course_index`.
4. **Study Notes Defacement**: User `student_123` attempts to delete a vital Class 12 notes document at `/notes/class12_maths`.
5. **Unauthorized MCQ Test Creation**: User `student_123` attempts to insert custom incorrect test papers in `/tests/exam_paper_1`.
6. **Result Hijacking**: User `student_123` attempts to write a test result payload with `userId: "student_456"` to spoof someone else's grades.
7. **Score Tampering**: User `student_123` attempts to overwrite their historical test score in `/testResults/result_9a12b` from 10 points to 100 points.
8. **Malicious Banner Inject**: User `student_123` attempts to overwrite Sushil Sir's public broadcast announcements at `/notifications/announcement_1`.
9. **Current Affairs Falsification**: User `student_123` attempts to update `/currentAffairs/bulletin_90` with fake mock news.
10. **Blog Spam Injection**: User `student_123` attempts to create a blog article inside `/blogs/my_spam_article` with random third-party ads.
11. **Anonymized DB Scraping**: Unauthenticated client attempts to query the entire `/users` index using blanket list reads.
12. **Created-At Spoofing**: User `student_123` attempts to bypass the immutable timestamp check by modifying `createdAt` during a profile update.

---

## 3. Security Test Runner (System Test Harness)

A validation harness using `@firebase/rules-unit-testing` logic to simulate access deny scenarios:

```typescript
import { initializeTestEnvironment, RulesTestEnvironment } from '@firebase/rules-unit-testing';
import * as fs from 'fs';

let testEnv: RulesTestEnvironment;

describe("PCM Plus Academy Security Rules Evaluation", () => {
  beforeAll(async () => {
    testEnv = await initializeTestEnvironment({
      projectId: "tactile-device-c6ppv",
      firestore: {
        rules: fs.readFileSync("firestore.rules", "utf8"),
        host: "localhost",
        port: 8080,
      }
    });
  });

  afterAll(async () => {
    await testEnv.cleanup();
  });

  test("Denies self-escalation role change", async () => {
    const student = testEnv.authenticatedContext("student_123");
    // Assert write returns PERMISSION_DENIED
  });

  // Additional mock assertions for all 12 pen-test payloads
});
```
