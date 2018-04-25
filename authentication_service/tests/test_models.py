import uuid
import datetime

from django.test import TestCase
from django.contrib.auth import get_user_model, hashers

from authentication_service.models import SecurityQuestion, \
    UserSecurityQuestion


class TestRegistrationModels(TestCase):

    @classmethod
    def setUpTestData(cls):
        super(TestRegistrationModels, cls).setUpTestData()
        cls.user = get_user_model().objects.create(
            username="AnswerTest@User@Name",
            birth_date=datetime.date(2000, 1, 1)
        )

        # Security questions
        cls.question_one = SecurityQuestion.objects.create(
            question_text="Some text for the one question"
        )
        cls.question_two = SecurityQuestion.objects.create(
            question_text="Some text for the other question"
        )

    def test_answer_hashing(self):
        text = "Some_text"
        answer = UserSecurityQuestion.objects.create(
            user=self.user,
            answer=text,
            language_code="en",
            question=self.question_one
        )
        self.assertTrue(hashers.check_password(text.lower(), answer.answer))

        text = " Some spacious _text "
        answer = UserSecurityQuestion.objects.create(
            user=self.user,
            answer=text,
            language_code="en",
            question=self.question_one
        )
        text = "Some spacious _text"
        self.assertTrue(hashers.check_password(text.lower(), answer.answer))

        self.assertIsNotNone(self.user.has_security_questions)


class UserModelTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        super(UserModelTestCase, cls).setUpTestData()
        cls.user = get_user_model().objects.create(
            username="username1", email="someverified@email.com",
            birth_date=datetime.date(2000, 1, 1)
        )
        cls.user.email_verified = True
        cls.user.save()

    def test_email_verification(self):
        # Change user email
        self.user.email = "notverified@email.com"
        self.user.save()

        # Check verification is false
        self.assertFalse(self.user.email_verified)

    def test_msisdn_verification(self):
        # Add user msisdn
        self.user.msisdn = "+27821234567"
        self.user.save()

        # Check verification is false
        self.assertFalse(self.user.msisdn_verified)

    def test_q_field(self):
        # "email", "first_name", "last_name", "msisdn", "nickname", "username"
        uid = uuid.uuid4()
        user = get_user_model().objects.create(
            username=f"{uid}",
            email=f"{uid}@email.com",
            first_name="AfirstName",
            last_name="LastName",
            msisdn="0865412369",
            nickname="N1ckN4m3",
            birth_date=datetime.date(2000, 1, 1)
        )

        self.assertEquals(
            user.q,
            f"{uid}@email.com AfirstName LastName 0865412369 N1ckN4m3 {uid}"
        )

        # Updates are a necessary evil.
        get_user_model().objects.filter(
            username=f"{uid}",
            email=f"{uid}@email.com",
            first_name="AfirstName",
            last_name="LastName",
            msisdn="0865412369",
            nickname="N1ckN4m3",
            birth_date=datetime.date(2000, 1, 1)
        ).update(first_name="Altered", last_name="AlteredLastName")

        user = get_user_model().objects.get(username=f"{uid}")
        self.assertEquals(
            user.q,
            f"{uid}@email.com AfirstName LastName 0865412369 N1ckN4m3 {uid}"
        )

        # Save will always trigger the field code path again.
        user.save()
        self.assertEquals(
            user.q,
            f"{uid}@email.com Altered AlteredLastName 0865412369 N1ckN4m3 {uid}"
        )
