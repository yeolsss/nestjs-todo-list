import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AuthService],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
describe('validateEmail', () => {
  it('should return true for valid email addresses', () => {
    const validEmails = [
      'test@example.com',
      'user.name@domain.com',
      'user-name@domain.co.uk',
      'user123@example.net',
      'user+tag@example.org',
    ];

    validEmails.forEach((email) => {
      expect(service['validateEmail'](email)).toBeTruthy();
    });
  });

  it('should return false for invalid email addresses', () => {
    const invalidEmails = [
      'plaintext',
      'missing@tld',
      '@missing-username.com',
      'spaces in@email.com',
      'missing.domain@',
      'multiple..dots@example.com',
      'special#chars@domain.com',
      'incomplete@.com',
    ];

    invalidEmails.forEach((email) => {
      // @ts-ignore - accessing private method for testing
      expect(service['validateEmail'](email)).toBeFalsy();
    });
  });
});
