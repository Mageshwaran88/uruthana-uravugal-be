import { Injectable, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as admin from 'firebase-admin';
import * as fs from 'fs';
import * as path from 'path';

export interface FirebaseDecodedToken {
  uid: string;
  phone_number?: string;
}

@Injectable()
export class FirebaseService implements OnModuleInit {
  private initialized = false;

  constructor(private config: ConfigService) {}

  onModuleInit() {
    const pathEnv = this.config.get<string>('firebase.serviceAccountPath');
    const jsonEnv = this.config.get<string>('firebase.serviceAccountJson');
    if (admin.apps.length > 0) return;

    try {
      if (jsonEnv) {
        const cred = JSON.parse(jsonEnv);
        admin.initializeApp({ credential: admin.credential.cert(cred) });
        this.initialized = true;
        return;
      }
      const jsonPath = pathEnv || process.env.GOOGLE_APPLICATION_CREDENTIALS;
      if (jsonPath && fs.existsSync(path.resolve(jsonPath))) {
        const cred = JSON.parse(fs.readFileSync(path.resolve(jsonPath), 'utf8'));
        admin.initializeApp({ credential: admin.credential.cert(cred) });
        this.initialized = true;
      }
    } catch (e) {
      console.warn('[Firebase] Init skipped:', (e as Error).message);
    }
  }

  isEnabled(): boolean {
    return this.initialized;
  }

  async verifyIdToken(idToken: string): Promise<FirebaseDecodedToken> {
    if (!this.initialized) {
      throw new Error('Firebase is not configured. Set FIREBASE_SERVICE_ACCOUNT_PATH or FIREBASE_SERVICE_ACCOUNT_JSON.');
    }
    const decoded = await admin.auth().verifyIdToken(idToken);
    return {
      uid: decoded.uid,
      phone_number: decoded.phone_number || undefined,
    };
  }
}
