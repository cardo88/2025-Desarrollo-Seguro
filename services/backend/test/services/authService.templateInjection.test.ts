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

describe('Mitigación Template Injection en email de alta (createUser)', () => {

  it('rechaza nombres con formato inválido (espera Invalid name format)', async () => {
    const maliciousUser = {
      id: 'u-evil',
      email: 'victim@example.com',
      password: 'x',
      first_name: '<img src=x onerror=alert(1)>',
      last_name: 'Last',
      username: 'someuser',
    } as User;

    const selectChainInvalid = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };
    mockedDb.mockReturnValueOnce(selectChainInvalid as any);

    await expect(AuthService.createUser(maliciousUser))
      .rejects
      .toThrow('Invalid name format');
  });

  it('escapa campos controlados por el usuario y mantiene el href seguro', async () => {
    const malicious: User = {
      id: 'u-evil',
      email: 'victim@example.com',
      password: 'x',
      first_name: "<%= 2 + 2 %>",
      last_name: '{{7*7}}',
      username: 'baduser"><svg onload=alert(2)>' as any,
    };

    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };
    const insertChain = {
      returning: jest.fn().mockResolvedValue([malicious]),
      insert: jest.fn().mockReturnThis(),
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    // Act
    await AuthService.createUser(malicious);

    // Mail enviado
    expect(sendMailMock).toHaveBeenCalled();
    const html = sendMailMock.mock.calls[0][0].html as string;

    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).not.toContain('<img src=x onerror=alert(1)>');

    expect(html).toContain('{{7*7}}');
    expect(html).not.toContain('49');

    expect(html).toMatch(/<a href="[^"]+">here<\/a>/i);
    expect(html).not.toMatch(/<%[-=]?[\s\S]*?%>/);
  });
});


