import type { Axios, AxiosInstance } from 'axios'

interface OAuth2ClientOptions {
  axios: Axios | AxiosInstance
  clientId: string
  clientSecret: string
  tokenEndpoint: string
  scopes?: string[]
}

export interface OAuth2ClientTokens {
  access_token: string
  expires_in: number
  refresh_token: string
  scope: string
  token_type: string
}

export interface OAuth2ClientTokensWithExpiration extends OAuth2ClientTokens {
  expires_at: number
}

export class TokenStore {
  private _promise: Promise<void> | null = null
  private onTokensRefreshedCallback: ((tokens: OAuth2ClientTokensWithExpiration) => void) | null = null

  constructor(private readonly options: OAuth2ClientOptions, private tokens: OAuth2ClientTokensWithExpiration) {
  }

  public onRefreshToken(callback: (tokens: OAuth2ClientTokensWithExpiration) => void): void {
    this.onTokensRefreshedCallback = callback
  }

  public async getAccessToken(): Promise<string> {
    if (this.accessTokenExpired())
      await this.refreshToken()

    return this.tokens.access_token
  }

  public getTokens(): OAuth2ClientTokensWithExpiration {
    return this.tokens
  }

  private async refreshToken(): Promise<void> {
    if (this._promise != null)
      return this._promise

    this._promise = new Promise((resolve, reject) => {
      this.options.axios
        .post<OAuth2ClientTokens>(
          this.options.tokenEndpoint,
          {
            grant_type: 'refresh_token',
            refresh_token: this.tokens.refresh_token,
            client_id: this.options.clientId,
            client_secret: this.options.clientSecret,
            scope: this.options.scopes?.join(' '),
          },
          {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
            },
          },
        )
        .then(({ data }) => {
          this.tokens = {
            ...data,
            expires_at: Date.now() + data.expires_in * 1000,
          }

          if (this.onTokensRefreshedCallback)
            this.onTokensRefreshedCallback(this.tokens)

          resolve()
        })
        .catch(() => {
          reject(new Error('Failed to refresh access token'))
        })
        .finally(() => {
          this._promise = null
        })
    })

    return this._promise
  }

  private accessTokenExpired(): boolean {
    return Date.now() >= this.tokens.expires_at
  }
}

export class OAuth2Client {
  constructor(private readonly options: OAuth2ClientOptions) {}

  public async login(username: string, password: string): Promise<TokenStore> {
    const { data } = await this.options.axios.post<OAuth2ClientTokens>(
      this.options.tokenEndpoint,
      {
        grant_type: 'password',
        username,
        password,
        client_id: this.options.clientId,
        client_secret: this.options.clientSecret,
        scope: this.options.scopes?.join(' '),
      },
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      },
    )

    const store = new TokenStore(this.options, {
      ...data,
      expires_at: Date.now() + data.expires_in * 1000,
    })

    return store
  }
}
