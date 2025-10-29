import nodemailer from 'nodemailer';
import AuthService from '../../src/services/authService';
import db from '../../src/db';
import { User } from '../../src/types/user';

jest.mock('../../src/db');
jest.mock('nodemailer');

const mockedDb = db as jest.MockedFunction<typeof db>;
const mockedNodemailer = nodemailer as jest.Mocked<typeof nodemailer>;

const sendMailMock = jest.fn().mockResolvedValue({ success: true });

beforeEach(() => {
  jest.clearAllMocks();
  mockedNodemailer.createTransport = jest.fn().mockReturnValue({
    sendMail: sendMailMock,
  } as any);
});

describe('Mitigación Template Injection en createUser', () => {

  it('rechaza entrada maliciosa si contiene código o tags (Invalid name format o Invalid characters)', async () => {
    const maliciousUser: User = {
      id: 'u-evil',
      email: 'victim@example.com',
      password: 'x',
      first_name: "<%= 2 + 2 %>",
      last_name: '{{7*7}}',
      username: '"><script>alert(1)</script>' as any,
    };

    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };

    const insertChain = {
      insert: jest.fn().mockReturnThis(),
      returning: jest.fn().mockResolvedValue([maliciousUser]),
    };

    mockedDb
      .mockReturnValueOnce(selectChain as any) 
      .mockReturnValueOnce(insertChain as any); 

    await expect(AuthService.createUser(maliciousUser))
      .rejects
      .toThrow(/Invalid name format|Invalid characters|Invalid username|Invalid email/);
  });
});
