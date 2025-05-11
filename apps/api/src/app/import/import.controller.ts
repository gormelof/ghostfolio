import { HasPermission } from '@ghostfolio/api/decorators/has-permission.decorator';
import { HasPermissionGuard } from '@ghostfolio/api/guards/has-permission.guard';
import { TransformDataSourceInRequestInterceptor } from '@ghostfolio/api/interceptors/transform-data-source-in-request/transform-data-source-in-request.interceptor';
import { TransformDataSourceInResponseInterceptor } from '@ghostfolio/api/interceptors/transform-data-source-in-response/transform-data-source-in-response.interceptor';
import { ConfigurationService } from '@ghostfolio/api/services/configuration/configuration.service';
import { TagService } from '@ghostfolio/api/services/tag/tag.service';
import { ImportResponse } from '@ghostfolio/common/interfaces';
import { hasPermission, permissions } from '@ghostfolio/common/permissions';
import type { RequestWithUser } from '@ghostfolio/common/types';

import {
  Body,
  Controller,
  Get,
  HttpException,
  Inject,
  Logger,
  Param,
  Post,
  Query,
  UseGuards,
  UseInterceptors
} from '@nestjs/common';
import { REQUEST } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { DataSource } from '@prisma/client';
import { StatusCodes, getReasonPhrase } from 'http-status-codes';

import { ImportDataDto } from './import-data.dto';
import { ImportService } from './import.service';

@Controller('import')
export class ImportController {
  public constructor(
    private readonly configurationService: ConfigurationService,
    private readonly importService: ImportService,
    private readonly tagService: TagService,
    @Inject(REQUEST) private readonly request: RequestWithUser
  ) {}

  @Post()
  @UseGuards(AuthGuard('jwt'), HasPermissionGuard)
  @HasPermission(permissions.createOrder)
  @UseInterceptors(TransformDataSourceInRequestInterceptor)
  @UseInterceptors(TransformDataSourceInResponseInterceptor)
  public async import(
    @Body() importData: ImportDataDto,
    @Query('dryRun') isDryRunParam = 'false'
  ): Promise<ImportResponse> {
    const isDryRun = isDryRunParam === 'true';

    if (
      !hasPermission(this.request.user.permissions, permissions.createAccount)
    ) {
      throw new HttpException(
        getReasonPhrase(StatusCodes.FORBIDDEN),
        StatusCodes.FORBIDDEN
      );
    }

    let maxActivitiesToImport = this.configurationService.get(
      'MAX_ACTIVITIES_TO_IMPORT'
    );

    const allTags = (importData.activities || [])
      .flatMap((a) => (Array.isArray(a.tags) ? a.tags : []))
      .filter((tag) => tag?.name)
      .map((tag) => tag.name);
    const uniqueTagNames = Array.from(new Set(allTags));
    if (uniqueTagNames.length) {
      const existingTags = await this.tagService.getTags();
      const existingTagNames = existingTags.map((t) => t.name);
      const newTagNames = uniqueTagNames.filter(
        (name) => !existingTagNames.includes(name)
      );
      if (newTagNames.length) {
        const canCreateOwnTag = hasPermission(
          this.request.user.permissions,
          permissions.createOwnTag
        );
        const canCreateTag = hasPermission(
          this.request.user.permissions,
          permissions.createTag
        );
        if (!canCreateOwnTag && !canCreateTag) {
          throw new HttpException(
            `Import contains new tags (${newTagNames.join(', ')}), but you do not have permission to create tags.`,
            StatusCodes.FORBIDDEN
          );
        }
      }
    }

    if (
      this.configurationService.get('ENABLE_FEATURE_SUBSCRIPTION') &&
      this.request.user.subscription.type === 'Premium'
    ) {
      maxActivitiesToImport = Number.MAX_SAFE_INTEGER;
    }

    try {
      const activities = await this.importService.import({
        isDryRun,
        maxActivitiesToImport,
        accountsDto: importData.accounts ?? [],
        activitiesDto: importData.activities,
        user: this.request.user
      });

      return { activities };
    } catch (error) {
      Logger.error(error, ImportController);

      throw new HttpException(
        {
          error: getReasonPhrase(StatusCodes.BAD_REQUEST),
          message: [error.message]
        },
        StatusCodes.BAD_REQUEST
      );
    }
  }

  @Get('dividends/:dataSource/:symbol')
  @UseGuards(AuthGuard('jwt'), HasPermissionGuard)
  @UseInterceptors(TransformDataSourceInRequestInterceptor)
  @UseInterceptors(TransformDataSourceInResponseInterceptor)
  public async gatherDividends(
    @Param('dataSource') dataSource: DataSource,
    @Param('symbol') symbol: string
  ): Promise<ImportResponse> {
    const activities = await this.importService.getDividends({
      dataSource,
      symbol
    });

    return { activities };
  }
}
