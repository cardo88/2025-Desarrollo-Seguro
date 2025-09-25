import db from '../db';
import { Invoice } from '../types/invoice';
import axios from 'axios';
import { promises as fs } from 'fs';
import * as path from 'path';
import dns from 'dns';

interface InvoiceRow {
  id: string;
  userId: string;
  amount: number;
  dueDate: Date;
  status: string;
}

const ALLOWED_PAYMENT_HOSTS = new Set([
  'visa',                 // servicio interno conocido
  'master',               // servicio interno conocido
  'payments.example.com'  // ejemplo de host externo permitido
]);

const PRIVATE_IP_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^::1$/,
  /^fc00:/,
  /^fe80:/
];

async function resolveHostname(hostname: string): Promise<string> {
  try {
    const res = await dns.promises.lookup(hostname);
    return res.address;
  } catch (err) {
    throw new Error('Could not resolve hostname');
  }
}

function isPrivateIp(ip: string): boolean {
  return PRIVATE_IP_RANGES.some(re => re.test(ip));
}

function normalizePaymentBrand(input: string): string {
  return input.replace(/^https?:\/\//i, '').trim();
}

class InvoiceService {

  static async list(userId: string, status?: string, operator?: string): Promise<Invoice[]> {
    let q = db<InvoiceRow>('invoices').where({ userId });

    if (status) {
      const allowedStatus = new Set(['paid', 'unpaid']);
      if (!allowedStatus.has(status)) {
        throw new Error('Invalid status');
      }

      const op = operator ?? '=';
      switch (op) {
        case '=':
          q = q.andWhere('status', status);
          break;
        case '!=':
          q = q.andWhereNot('status', status);
          break;
        default:
          throw new Error('Invalid operator');
      }
    }

    const rows = await q.select('id', 'userId', 'amount', 'dueDate', 'status');
    return rows.map(row => ({
      id: row.id,
      userId: row.userId,
      amount: row.amount,
      dueDate: row.dueDate,
      status: row.status
    }));
  }

  static async setPaymentCard(
    userId: string,
    invoiceId: string,
    paymentBrand: string,
    ccNumber: string,
    ccv: string,
    expirationDate: string
  ) {
    const normalized = normalizePaymentBrand(paymentBrand);
    const [hostnamePart, portPart] = normalized.split(':');
    const hostname = hostnamePart;
    const port = portPart ? parseInt(portPart, 10) : 80;

    if (!ALLOWED_PAYMENT_HOSTS.has(hostname)) {
      throw new Error('Payment host not allowed');
    }

    const ip = await resolveHostname(hostname).catch(() => { 
      throw new Error('Could not resolve payment host'); 
    });
    if (isPrivateIp(ip)) {
      throw new Error('Payment host resolves to a private address');
    }

    const url = `http://${hostname}:${port}/payments`;

    let paymentResponse;
    try {
      paymentResponse = await axios.post(url, {
        ccNumber,
        ccv,
        expirationDate
      }, {
        maxRedirects: 0,
        timeout: 5000
      });
    } catch (err: any) {
      throw new Error('Payment failed');
    }

    if (paymentResponse.status !== 200) {
      throw new Error('Payment failed');
    }

    await db('invoices')
      .where({ id: invoiceId, userId })
      .update({ status: 'paid' });
  }

  static async getInvoice(invoiceId: string): Promise<Invoice> {
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    return invoice as Invoice;
  }

  static async getReceipt(invoiceId: string, pdfName: string) {
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    try {
      const filePath = `/invoices/${pdfName}`;
      const content = await fs.readFile(filePath, 'utf-8');
      return content;
    } catch (error) {
      console.error('Error reading receipt file:', error);
      throw new Error('Receipt not found');
    }
  }
}

export default InvoiceService;
