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

type GrantType = 'ad' | 'password' | 'refresh_token'

interface ClientOptions {
  client_id: string
  code?: string
  state?: string
  username?: string
  password?: string
  client_secret: string
  grant_type: GrantType
  scope?: string
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

  private getRefreshToken(): string {
    return this.tokens.refresh_token
  }

  private setTokens(tokens: OAuth2ClientTokensWithExpiration): void {
    this.tokens = tokens
    this.onTokensRefreshedCallback?.(tokens)
  }

  private async refreshToken(): Promise<void> {
    if (this._promise != null)
      return this._promise

    this._promise = new Promise((resolve, reject) => {
      this.getNewAccessToken(this.getRefreshToken())
        .then((tokens) => {
          this.setTokens(tokens)
          resolve()
        })
        .catch(() => {
          console.error('Failed to refresh access token, trying again...')

          setTimeout(() => {
            this.getNewAccessToken(this.getRefreshToken())
              .then((tokens) => {
                this.setTokens(tokens)
                resolve()
              })
              .catch(() => {
                reject(new Error('Failed to refresh access token'))
              })
          }, 1000)
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

  private async getNewAccessToken(refreshToken: string): Promise<OAuth2ClientTokensWithExpiration> {
    const response = await this.options.axios.post<OAuth2ClientTokens>(
      this.options.tokenEndpoint,
      {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
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

    return {
      refresh_token: response.data.refresh_token,
      token_type: response.data.token_type,
      expires_in: response.data.expires_in,
      scope: response.data.scope,
      access_token: response.data.access_token,
      expires_at: Date.now() + response.data.expires_in * 1000,
    }
  }
}

export class OAuth2Client {
  constructor(private readonly options: OAuth2ClientOptions) {}

  public async loginPassword(username: string, password: string): Promise<TokenStore> {
    return this.login({
      grant_type: 'password',
      username,
      password,
      client_id: this.options.clientId,
      client_secret: this.options.clientSecret,
      scope: this.options.scopes?.join(' '),
    })
  }

  public async loginAuthorization(code: string, state: string, grantType: GrantType): Promise<TokenStore> {
    return this.login({
      grant_type: grantType,
      code,
      state,
      client_id: this.options.clientId,
      client_secret: this.options.clientSecret,
      scope: this.options.scopes?.join(' '),
    })
  }

  private async login(clientOptions: ClientOptions): Promise<TokenStore> {
    const { data } = await this.options.axios.post<OAuth2ClientTokens>(this.options.tokenEndpoint, clientOptions, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    })

    return new TokenStore(this.options, {
      ...data,
      expires_at: Date.now() + data.expires_in * 1000,
    })
  }
}
